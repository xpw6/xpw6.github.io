---
title: "When the Request Picks the Algorithm: HMAC Downgrade in Symfony's Mailomat Webhook Parser (CVE-2026-48747)"
date: 2026-06-12T12:00:00+03:00
draft: false
showToc: true
hideSummary: true
---

# When the Request Picks the Algorithm: HMAC Downgrade in Symfony's Mailomat Webhook Parser (CVE-2026-48747)

Note: My friends Omar Alshammari and Alwaleed Alshammari and I reported this issue to the Symfony security team. It was assigned **CVE-2026-48747** (advisory `GHSA-rrj9-5q2j-4gvr`) and fixed by Nicolas Grekas in Symfony **7.4.13** and **8.0.13**. It's a textbook algorithm-downgrade bug: the kind that hides in a four-line function and slips past review because the code *looks* like it's doing signature verification. This write-up breaks down the root cause, what it gives an attacker, and the fix.

## Background: How Symfony Authenticates an Inbound Webhook

When you wire a transactional email provider into a Symfony application, you usually get two directions of traffic. Outbound is the mail you send. Inbound is the stream of events the provider sends *back* to you over a webhook: delivered, bounced, marked as spam, opened, and so on. Symfony's Webhook and RemoteEvent components turn those raw HTTP requests into typed `RemoteEvent` objects that the rest of your application can react to, like suppressing a hard-bounced address, flagging a complaint, or updating delivery state.

That inbound webhook is a security boundary. Anyone on the internet can `POST` to your webhook endpoint. The only thing standing between a real provider event and an attacker-fabricated one is the signature check. If I can forge a signature, I can inject any event I want: tell your application an address bounced so it stops mailing a victim, fake a "delivered" to hide a failure, or trigger whatever business logic you hang off a complaint event.

[Mailomat](https://www.mailomat.swiss/) is a Swiss email provider with a Symfony Mailer bridge (`symfony/mailomat-mailer`, introduced in 7.2). Its webhooks are authenticated with an HMAC. Each request carries four headers:

| Header | Meaning |
| :--- | :--- |
| `X-MOM-Webhook-ID` | unique event id |
| `X-MOM-Webhook-Event` | event type, e.g. `delivered` |
| `X-MOM-Webhook-Timestamp` | unix timestamp |
| `X-MOM-Webhook-Signature` | the HMAC, in the form `algo=signature` |

The receiver recomputes the HMAC over `id.event.timestamp` using a shared secret and compares it to the signature in the header. Mailomat's own [webhook-security documentation](https://api.mailomat.swiss/docs/#tag/webhook-security) specifies the primitive: **HMAC-SHA256**. Hold onto that fact.

## The Vulnerable Code

Here is the entire verification routine as it shipped, in `Symfony\Component\Mailer\Bridge\Mailomat\Webhook\MailomatRequestParser`:

```php
private function validateSignature(HeaderBag $headers, #[\SensitiveParameter] string $secret): void
{
    // see https://api.mailomat.swiss/docs/#tag/webhook-security
    $data = implode('.', [
        $headers->get(self::HEADER_ID),
        $headers->get(self::HEADER_EVENT),
        $headers->get(self::HEADER_TIMESTAMP),
    ]);

    [$algo, $signature] = explode('=', $headers->get(self::HEADER_SIGNATURE));
    if (!hash_equals(hash_hmac($algo, $data, $secret), $signature)) {
        throw new RejectWebhookException(406, 'Signature is wrong.');
    }
}
```

At a glance this is fine. It builds the canonical message, computes an HMAC, and uses `hash_equals()` for a constant-time comparison. The author even knew to avoid `==`. So where is the bug?

## The Root Cause: The Sender Chooses Its Own Verifier

Look at one line:

```php
[$algo, $signature] = explode('=', $headers->get(self::HEADER_SIGNATURE));
```

`$algo` is the left half of the `X-MOM-Webhook-Signature` header, a value that arrives **on the wire, from whoever sent the request**. It's then handed straight to `hash_hmac()`:

```php
hash_hmac($algo, $data, $secret)
```

`hash_hmac()` doesn't care that Mailomat documents SHA-256. Its only constraint is that `$algo` names an algorithm PHP can wrap in HMAC. That set is large, and it includes primitives with known cryptanalysis: `md5`, `sha1`, `md4`, `ripemd128`, `tiger128,3`, and more. The server has delegated the choice of cryptographic primitive to the unauthenticated party it's trying to authenticate.

This is the canonical **algorithm-confusion / downgrade** shape (CWE-347, *Improper Verification of Cryptographic Signature*, combined with CWE-757, *Selection of Less-Secure Algorithm During Negotiation*). If you've seen the JWT `alg=none` and `RS256→HS256` attacks, you've seen this exact mistake: the token, or here the request, is allowed to tell the verifier *how* to verify it. A trustworthy verifier never takes verification instructions from untrusted input.

Here is how it breaks down step by step:

* **Attacker-controlled input:** `$algo` comes directly from the `X-MOM-Webhook-Signature` header. There is no allow-list, no comparison against an expected value.
* **Dangerous sink:** `hash_hmac($algo, ...)` will compute an HMAC under whatever primitive `$algo` names, weak ones included.
* **No pinning:** Mailomat says SHA-256. The parser never enforces it. The documented contract and the implemented check disagree.
* **Comparison against the same attacker-influenced primitive:** the right-hand `$signature` is also attacker-supplied, and it's compared against the HMAC of the *attacker-selected* algorithm. The whole check floats to whatever primitive the request names.

## Impact

The verifier's strength is now bounded by the *weakest* HMAC primitive PHP exposes, and the attacker chooses it, not the server. Pin SHA-256 and the floor is fixed; read the algorithm off the wire and the floor drops to whatever primitive an attacker names in the header. The day any of those primitives gets a practical break, every Mailomat receiver on a vulnerable Symfony inherits it with no code change. This is exactly why "let the message choose its own verification" is a recognized vulnerability class, with JWT `alg` confusion as the canonical example.

Worth stating precisely: HMAC-MD5 doesn't collapse the moment MD5 loses collision resistance, since HMAC remains a pseudo-random function on top of a broken hash, so there's no drop-in, secret-less forgery against today's primitives. The bug lives in the design, not in one specific broken hash, and it removes the guarantee the receiver was relying on.

## Reproducing the Downgrade

You don't need to break any crypto to *demonstrate* the flaw. You only need to show that the parser honors an algorithm it should have rejected. That's precisely what the regression test Symfony added asserts: under the old code, a request signed with `md5`, `sha1`, or `sha512` is accepted instead of being refused.

Conceptually, against the vulnerable parser, a request shaped like this is validated under MD5:

```http
POST /webhook/mailer_mailomat HTTP/1.1
Host: victim.example
Content-Type: application/json
X-MOM-Webhook-ID: 1d958822-0934-4c6a-abc8-5defec4baa64
X-MOM-Webhook-Event: delivered
X-MOM-Webhook-Timestamp: 1718004211
X-MOM-Webhook-Signature: md5=<hmac_md5(id.event.timestamp, secret)>

{ ...event body... }
```

The old `validateSignature()` reads `md5`, computes `hash_hmac('md5', "id.event.timestamp", $secret)`, and accepts the request. The verifier has been moved off SHA-256 entirely by a single header field, which is the precondition for every downgrade attack. A short PHP harness makes the behavior explicit:

```php
$data = implode('.', [$id, $event, $timestamp]);

// What the wire says to use, not what Mailomat documents:
$algo = 'md5';                       // attacker-chosen via X-MOM-Webhook-Signature
$sig  = hash_hmac($algo, $data, $secret);

// The vulnerable check passes, because the request set the primitive:
var_dump(hash_equals(hash_hmac($algo, $data, $secret), $sig)); // bool(true)
```

The point is not that MD5 is forgeable today. The point is that nothing in the verifier insists on SHA-256, so the security of the check is decided by the request, not by the server.

## A Family of Webhook-Verification Bugs

This finding didn't appear in isolation. In the same window, Symfony's webhook parsers got a coordinated audit, and the same underlying question of who controls verification produced several CVEs:

* **CVE-2026-45755** (Mailtrap): the parser never verified the `X-Mt-Signature` HMAC **at all**.
* **CVE-2026-47212** (Twilio): the Notifier webhook parser never verified the `X-Twilio-Signature` HMAC **at all**.
* **CVE-2026-48747** (Mailomat, this post): the parser *did* verify an HMAC, but let the request pick the algorithm.

Three bridges, three flavors of the same root cause: a signature check that doesn't actually constrain what it's checking. Mailtrap and Twilio forgot to check; Mailomat checked, but against attacker-chosen rules. If you maintain integrations like these, the lesson generalizes immediately.

## The Fix

The patch ([commit `bdfe9fe`](https://github.com/symfony/symfony/commit/bdfe9fe0d94d33dfaca0bc2fe0b00b54767b0c88)) is two lines, and every character earns its place:

```php
[$algo, $signature] = explode('=', $headers->get(self::HEADER_SIGNATURE), 2) + [1 => ''];
if ('sha256' !== $algo || !hash_equals(hash_hmac('sha256', $data, $secret), $signature)) {
    throw new RejectWebhookException(406, 'Signature is wrong.');
}
```

What changed:

* **The algorithm is pinned, not read.** `hash_hmac('sha256', ...)` uses a hardcoded primitive. The wire no longer influences which HMAC is computed.
* **The declared algorithm is validated, not trusted.** `'sha256' !== $algo` rejects any request whose header announces anything other than `sha256`, including every weak primitive PHP would otherwise have accepted.
* **The header is parsed defensively.** `explode('=', ..., 2)` caps the split so a signature value containing `=` is preserved, and `+ [1 => '']` guarantees a defined `$signature` even when the header has no `=` at all, instead of tripping an undefined-index warning on malformed input.
* **The comparison stays constant-time.** `hash_equals()` was already correct and was kept.

The shape to internalize: the server decides the algorithm; the request may only present a signature *for that algorithm*. Anything else is rejected before a single byte of crypto runs against attacker-chosen rules.

## Takeaways for Auditors and Developers

Signature verification is one of those areas where code that *looks* careful can still be wrong, because the bug is in what the check *fails to constrain* rather than in an obviously missing step. A few things I now check first whenever I read a verifier:

* **Where does the algorithm come from?** If the primitive is read from the message, like a JWT `alg`, a `scheme=` prefix, or an `algo=signature` header, that's a finding until proven otherwise. Pin it server-side and reject anything else.
* **Does the implementation match the provider's documented scheme?** Mailomat documented SHA-256; the bridge ignored it. Cross-check the spec against the code, not against the variable names.
* **Is a missing or malformed signature rejected, not defaulted?** Empty strings, absent headers, and unexpected formats should fail closed. (See the Mailtrap and Twilio siblings, where the check was absent entirely.)
* **Is the comparison constant-time?** `hash_equals()` in PHP, `crypto.timingSafeEqual` in Node, `hmac.compare_digest` in Python. `==` is a finding on its own.
* **Is the signed message canonical and unambiguous?** Make sure an attacker can't shift bytes between fields to keep the same HMAC over different semantics.

The mistake here was not laziness. The author reached for `hash_hmac()` and `hash_equals()`, the right tools. It was trusting one field that should never have been trusted. Treat the algorithm selector as adversarial input, the same way you'd treat the signature itself, and this entire class of bug disappears.

## References

* Symfony advisory: [GHSA-rrj9-5q2j-4gvr](https://github.com/symfony/symfony/security/advisories/GHSA-rrj9-5q2j-4gvr), *Mailomat Mailer Webhook Parser Reads the HMAC Algorithm from the Request: Signature Algorithm Downgrade* (CVE-2026-48747)
* Fix: [symfony/symfony@bdfe9fe](https://github.com/symfony/symfony/commit/bdfe9fe0d94d33dfaca0bc2fe0b00b54767b0c88), *[Mailer] Pin Mailomat webhook signature algorithm to SHA-256*
* Affected: `symfony/mailomat-mailer` and `symfony/symfony` `>=7.2,<7.4.13` and `>=8.0,<8.0.13`. Fixed in **7.4.13** and **8.0.13** (forward-ported to 8.1).
* CWE-347 (Improper Verification of Cryptographic Signature), CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
* Reported by Omar Alshammari, Essam Alanazi, and Alwaleed Alshammari. Fix by Nicolas Grekas.
