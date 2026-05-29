---
layout: post
title: "Request Smuggling Is a Parser Disagreement Bug"
date: 2026-06-17 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [http-request-smuggling, portswigger, http2, cache-poisoning, browser-security]
related_posts:
  - ssrf-is-a-network-position-bug
  - web-cache-deception-five-labs
  - xss-is-a-parser-boundary-problem
---

HTTP request smuggling looks like a bag of weird headers until you reduce it to one question:

**Where does this component think the request ends?**

The 22 PortSwigger request smuggling labs are a good map because they keep changing one variable at a time: `Content-Length`, `Transfer-Encoding`, HTTP/2 downgrade behavior, cache interaction, browser connection reuse, and timing. The durable lesson is that the vulnerability is not a magic payload. It is a disagreement between parsers.

## The parser map

The basic classes are small:

| Class | Front-end view | Back-end view |
|-------|----------------|---------------|
| CL.TE | body length comes from `Content-Length` | body length comes from chunked `Transfer-Encoding` |
| TE.CL | body length comes from chunked `Transfer-Encoding` | body length comes from `Content-Length` |
| H2.CL | HTTP/2 request is framed cleanly | downgraded HTTP/1 request trusts `Content-Length` |
| H2.TE | HTTP/2 request should not use chunked coding | downgraded HTTP/1 request honors `Transfer-Encoding` |
| CL.0 | client declares a body | an endpoint ignores the body |
| 0.CL | one side sees zero body | another side still consumes body bytes |

Once you know which parser consumes which bytes, the payload becomes mechanical.

## CL.TE is about leaving bytes after the zero chunk

A minimal CL.TE probe looks like this:

```http
POST / HTTP/1.1
Host: LAB
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The front end forwards six bytes of body. The back end sees a zero-length chunk and treats the trailing `G` as the prefix of the next request. Send a second `POST`, and the back end sees `GPOST`.

For a cleaner oracle, smuggle:

```http
GET /404 HTTP/1.1
X-Ignore: X
```

If the following request gets a 404, the byte queue is desynchronized.

## TE.CL is about a tiny back-end body

TE.CL reverses the trust. The front end processes a valid chunked body, while the back end only consumes a tiny `Content-Length`:

```http
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Length: 15

x=1
0

```

The back end consumes only `5c\r\n`. Everything after that is queued as the next request.

The obfuscated-TE lab is the same idea with parser disagreement over duplicate headers:

```http
Transfer-Encoding: chunked
Transfer-encoding: cow
```

One component believes `chunked`; the other falls back to content length.

## Impact starts with trust boundaries

The first useful escalation is the admin panel. The front end blocks `/admin`, but the back end accepts it when the request appears local:

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Length: 10

x=
```

That inner content length absorbs bytes from the next real request so that its headers do not collide with the smuggled `Host`.

One lab hides the name of the front-end client-IP header. The trick is to smuggle a search request with an oversized body, causing the rewritten headers to be reflected in the `search` parameter. Once the `X-*-IP` header name is known, the admin request can claim `127.0.0.1`.

## Victim-state impact changes the timing

Request capture stores the next user's HTTP request as a comment. Reflected XSS queues a blog-post response whose hidden form reflects the `User-Agent`:

```http
User-Agent: a"/><script>alert(1)</script>
```

In both cases, the attacker is not consuming their own response. The exploit is positioned so the next user or the next browser resource request receives it.

That same timing problem appears again in the cache labs. Web cache poisoning turns a JavaScript resource into a redirect to attacker-controlled JavaScript. Web cache deception makes an account page land under a static-resource cache key. The practical trap is self-poisoning: fetching the cache key too early can store a login redirect or harmless response before the victim arrives.

## HTTP/2 bugs are downgrade bugs

HTTP/2 does not have an HTTP/1 request line and does not need chunked transfer coding. The vulnerable point is often the front end's HTTP/2-to-HTTP/1 downgrade.

H2.TE keeps `Transfer-Encoding` alive through downgrade. H2.CL keeps a misleading `Content-Length`. CRLF injection in H2 headers lets an attacker synthesize HTTP/1 headers during downgrade:

```text
foo: bar\r\n
Transfer-Encoding: chunked
```

Request splitting goes one step further and creates a second request inside the downgraded stream.

Request tunnelling is the variant to remember. It does not need back-end connection reuse. Instead, a single downgraded HTTP/2 request contains a tunnelled HTTP/1 request, often injected through a header name or `:path` pseudo-header. This is why the mitigation cannot stop at "disable upstream connection reuse."

## Browser-powered desync makes the victim own the connection

CL.0 and 0.CL move the bug closer to browser behavior:

- CL.0: the browser sends a body, but the endpoint ignores it.
- 0.CL: one side believes there is no body, while another side keeps reading.

Client-side desync uses the victim's browser as the connection owner. The exploit page causes the browser to send a desynchronizing request and then a follow-up request on the same connection. Pause-based smuggling adds a timeout primitive: send headers, wait long enough for the back-end body read to time out without closing the connection, then append the smuggled request.

These are harder to reason about because the attacker controls less of the transport. The model is still the same: which component consumes which bytes?

## Defender notes

Hardening:

- reject ambiguous requests containing both `Content-Length` and `Transfer-Encoding`;
- reject duplicate, malformed, or mixed-case `Transfer-Encoding` variants instead of normalizing them differently across layers;
- strip HTTP/1-only length headers during HTTP/2 downgrade;
- forbid CRLF in HTTP/2 header names, values, and pseudo-header values;
- close upstream connections after ambiguous or invalid requests;
- avoid cross-user upstream connection reuse where possible;
- do not use `Host: localhost`, client-IP headers, or front-end-added headers as standalone admin authentication;
- mark authenticated pages `Cache-Control: private, no-store`;
- regression-test redirecting directories, static resources, and framework routes for CL.0 and 0.CL behavior.

Detection:

- CL and TE in the same request;
- duplicate TE or invalid TE values;
- bodies containing `0\r\n\r\nGET /`;
- back-end methods such as `GPOST`;
- nested request lines and `Host` headers in body fields;
- HTTP/2 requests containing HTTP/1-only length headers;
- H2 header values or pseudo-headers containing `HTTP/1.1` or newline-like bytes;
- static resources returning account HTML, redirects, or unexpected JavaScript origins;
- comments or profile fields containing raw cookies and HTTP headers;
- response queue anomalies where one client receives another user's account or admin response.

The useful mindset is parser accounting. Before thinking about impact, account for every byte: who reads it, who forwards it, who queues it, and who receives the response.
