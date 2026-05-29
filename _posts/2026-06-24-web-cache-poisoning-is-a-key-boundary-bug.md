---
layout: post
title: "Web Cache Poisoning Is a Key Boundary Bug"
date: 2026-06-24 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [web-cache-poisoning, cache-keys, xss, portswigger]
related_posts:
  - path-traversal-is-a-canonicalization-bug
  - request-smuggling-is-a-parser-disagreement
  - web-cache-deception-is-a-routing-mismatch
---

Web cache poisoning is not mainly about whether a response is cached. It is about whether the cache key represents every input that can change that response.

The thirteen PortSwigger labs make this precise. The poisoned input changes across the series: forwarding headers, cookies, query strings, excluded UTM parameters, GET bodies, URL paths, language settings, CORS headers, and internal fragments. The invariant stays the same: the origin sees one request shape, the cache keys another.

## The three questions

For any candidate endpoint, ask:

1. What proves cache reuse?
2. Which inputs influence the response?
3. Which of those inputs are absent, transformed, or incorrectly escaped in the key?

`X-Cache`, `Age`, and `Pragma: x-get-cache-key` are oracles. A cache buster is a safety rail while testing. Without one, you can mistake your own poisoned object for a reliable primitive.

## Unkeyed inputs are direct poison

The simplest labs use unkeyed headers and cookies. `X-Forwarded-Host` changes a script import:

```html
<script src="//HOST/resources/js/tracking.js"></script>
```

If the cache ignores that header, the homepage can be cached with an attacker-controlled script origin.

The cookie variant is the same failure in JavaScript-string form:

```http
Cookie: fehost=someString"-alert(1)-"someString
```

The multiple-header lab is a useful reminder: some bugs only appear when two inputs are combined. One header triggers a redirect; another controls the redirect host.

## Parser disagreement expands the surface

The implementation labs are more interesting because the input may appear keyed at first.

An excluded analytics parameter can still be dangerous when the page reflects the full URL:

```http
GET /?utm_content='/><script>alert(1)</script>
```

Parameter cloaking uses a `;` disagreement. The cache treats the following as one excluded parameter, while the backend sees a second JSONP callback:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

Fat GET is the same class with a different boundary: the backend reads a GET body, the cache key does not.

## Normalization turns edge cases into impact

URL normalization is what makes several expert cases practical. A raw path can be cached by a proxy and later reached by a browser through its encoded equivalent. A backslash can become a forward slash at one layer but remain a cacheable redirect at another.

The internal-cache lab adds one more layer: the outer cache keys on the query string, but an internal fragment cache ignores it. Repeated requests eventually poison only the fragment that emits a JavaScript URL.

## Cache key injection is delimiter abuse

The expert cache-key-injection lab is the densest chain:

- an excluded `utm_content` parameter;
- client-side parameter pollution into `/js/localize.js`;
- response header injection through `origin` when `cors=1`;
- cache-key delimiter injection that lets URL content impersonate a keyed header component.

The important lesson is not the exact string. It is that cache keys built by concatenating components must escape delimiters structurally. A key is data, not a log line.

## Defender notes

Hardening:

- include every response-influencing input in the key, or do not cache the response;
- strip untrusted `X-Forwarded-*`, `Forwarded`, `X-Host`, and `X-Original-URL` headers at the edge;
- keep cache and origin URL normalization identical;
- avoid caching reflected error pages, login redirects, personalized content, and `Set-Cookie` responses;
- encode cache key components structurally instead of joining strings with delimiters;
- pin script and JSON origins, and validate third-party JSON before it reaches DOM sinks.

Detection:

- repeated `miss -> hit` cycles with unusual forwarding headers;
- public cached HTML/JS/JSON containing external hosts, `%0d%0a`, event handlers, or `alert(`;
- `Pragma: x-get-cache-key` and header-guessing traffic;
- cached JavaScript or JSON resources that differ from origin baselines;
- poisoning attempts inside rare `Vary` buckets such as one specific User-Agent.

The durable rule is that cache behavior is application behavior. Treat the cache key like an authorization decision: incomplete inputs create cross-user trust failures.
