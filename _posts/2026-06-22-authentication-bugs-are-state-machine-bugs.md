---
layout: post
title: "Authentication Bugs Are State Machine Bugs"
date: 2026-06-22 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [authentication, mfa, password-reset, portswigger]
related_posts:
  - authorization-is-not-a-route-name
  - xss-is-a-parser-boundary-problem
  - csrf-tokens-do-not-prove-user-intent
---

Authentication testing is easiest when you stop thinking about a single login form.

Think about a state machine:

```text
identify -> password verify -> MFA -> session -> remember-me -> reset/change password
```

The 14 PortSwigger authentication labs break one edge of that machine at a time.

## The map

| Class | Example |
|-------|---------|
| username oracle | different text, subtle text, timing, account lock |
| brute-force logic flaw | successful login resets failure counter |
| MFA state flaw | password-authenticated user can browse to account page |
| MFA binding flaw | client chooses `verify=carlos` |
| remember-me weakness | `base64(username:md5(password))` |
| reset logic flaw | token not checked on final password reset |
| reset poisoning | `X-Forwarded-Host` controls reset link host |
| change-password oracle | error message reveals correct current password |
| bulk credentials | JSON password array processed as one request |

## Username oracles are not always obvious

The easy version returns different text:

```text
Invalid username
Incorrect password
```

The subtle version differs only by punctuation or whitespace. The timing version takes longer for valid usernames when a long password forces extra work. Account lock creates another oracle because only real accounts reach the lock state.

The defensive requirement is uniformity: text, status, length, and timing should not disclose which identity step succeeded.

## Rate limits need the right key

One brute-force lab can be bypassed by interleaving a known valid login:

```text
carlos:candidate
wiener:peter
carlos:next-candidate
wiener:peter
```

Another accepts a JSON array:

```json
{
  "username": "carlos",
  "password": ["123456", "password", "qwerty"]
}
```

The protection counts requests, but the application tries multiple credentials inside one request.

Rate limits need to understand usernames, source behavior, device/session state, and request semantics.

## MFA must bind the challenge

The simple bypass is a missing state check: after password authentication, the user can directly browse to `/my-account`.

The broken-logic MFA lab lets the client decide which user is being verified:

```text
verify=carlos
```

The brute-force MFA lab requires rebuilding the login state before each code attempt:

```text
GET /login
POST /login
GET /login2
POST /login2 mfa-code=0000..9999
```

The invariant is that MFA code, user, session, challenge, purpose, and expiry must be tied together server-side.

## Reset links and remember-me cookies are authentication too

The broken reset lab ignores the reset token at the final step and trusts a hidden username field. The reset-poisoning lab builds reset links from `X-Forwarded-Host`, letting an attacker receive the victim's token in an access log.

Remember-me cookies fail when they are deterministic:

```text
base64(username + ":" + md5(password))
```

That format can be generated for candidate passwords or cracked offline after cookie theft. A safe persistent login token should be random, server-side verifiable, revocable, and unrelated to the password hash.

## Defender notes

Hardening:

- unify login failure text, status, length, and timing;
- rate-limit by username, IP, device/session, and global risk signals;
- bind MFA challenges to user, session, purpose, and expiry;
- require MFA-complete state before protected resources;
- bind reset tokens to user and action, then validate them on the final action;
- generate reset links from fixed server configuration;
- use random server-side remember-me tokens;
- unify password-change error messages;
- reject type changes such as password string to array.

Detection:

- dictionary-shaped username or password attempts;
- rotating `X-Forwarded-For` on login requests;
- many MFA code submissions in sequence;
- password reset requests with abnormal Host or `X-Forwarded-Host`;
- remember-me cookies that decode to `username:hash`;
- successful known-account logins interleaved with victim attempts;
- JSON password fields submitted as arrays.

The useful habit is state accounting. For every authentication step, ask what fact was proven, where it is stored, which user it is bound to, and whether the next step actually checks it.
