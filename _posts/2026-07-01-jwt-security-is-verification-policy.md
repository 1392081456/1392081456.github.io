---
layout: post
title: "JWT Security Is Verification Policy"
date: 2026-07-01 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [jwt, jwk, jku, algorithm-confusion, portswigger]
related_posts:
  - oauth-security-is-binding
  - authentication-bugs-are-state-machine-bugs
  - authorization-is-not-a-route-name
---

JWTs are easy to mistake for security because they look structured and cryptographic. The structure is not the security. The verification policy is.

The eight PortSwigger JWT labs move through the usual failure modes: no verification, `alg:none`, weak HMAC secrets, attacker-controlled keys, `kid` injection, and algorithm confusion.

## Decode is not verify

The first failure is using a JWT library to parse claims without verifying the signature. If changing:

```json
{"sub":"administrator"}
```

works without re-signing, the server is authenticating decoded JSON, not a verified token.

The `alg:none` variant is only slightly different. The token declares:

```json
{"alg":"none","typ":"JWT"}
```

and leaves the signature empty:

```text
header.payload.
```

No authentication system should accept this mode.

## HMAC secrets are credentials

Weak HMAC secrets turn JWTs into offline password-cracking targets:

```bash
hashcat -a 0 -m 16500 <jwt> jwt.secrets.list
```

Once the secret is recovered, claims can be changed and re-signed. Treat HMAC JWT secrets like passwords with high entropy and rotation requirements.

## Key discovery must be trusted

The key-header labs are all versions of the same bug: the attacker influences which key verifies their token.

`jwk` embeds a public key directly in the header. `jku` points the server to an attacker-hosted JWKS. `kid` is supposed to select a known key, but becomes path traversal:

```json
{"kid":"../../../../../../../dev/null"}
```

Key IDs should be opaque references into a trusted registry. They should not be URLs, files, or queries selected by the token.

## Algorithm confusion is type confusion for keys

RS256 uses a private key to sign and a public key to verify. HS256 uses one shared secret for both.

Algorithm confusion appears when the verifier trusts the token's `alg` and uses an RSA public key as an HMAC secret:

```json
{"alg":"HS256"}
```

If the public key is exposed, it can be used to sign a forged HS256 token. If it is not exposed, it may still be derived from multiple valid RS256 tokens. The private key is not broken; the verifier's key-type policy is.

## Defender notes

Hardening:

- pin accepted algorithms server-side;
- reject `none`;
- use verify APIs for authentication paths;
- use strong managed secrets for HMAC;
- treat `jwk`, `jku`, and `kid` as trusted-registry selectors only;
- allowlist JWKS origins;
- validate `kid` as an opaque ID;
- keep HS and RS verification code paths separate;
- avoid trusting high-risk authorization claims without server-side checks.

Detection:

- `alg:none`;
- unexpected `jwk` or external `jku`;
- `kid` containing traversal or `/dev/null`;
- RS256 tokens suddenly becoming HS256;
- role or subject jumps without a fresh login;
- outbound JWKS fetches to unfamiliar hosts.

JWT failures are usually policy failures. The token says what it wants to be; the server must decide what it is willing to verify.
