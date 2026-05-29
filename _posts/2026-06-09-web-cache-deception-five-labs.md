---
layout: post
title: "Five Ways a Cache and an Origin Disagree — A Web Cache Deception Map"
date: 2026-06-09 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [web-cache-deception, caching, csrf, portswigger, normalization]
related_posts:
  - 18-sqli-labs-from-tautologies-to-oob
  - four-ways-llm-apps-turn-data-into-actions
---

Web cache deception (WCD) has one idea behind it: **the cache and the origin disagree about what a URL means.** The cache decides a response is a static asset and stores it in a shared, cookie-agnostic cache; the origin resolves the same URL to a dynamic, authenticated page. The victim's private response — API key, CSRF token — ends up sitting at a URL the attacker can fetch.

I worked the five PortSwigger WCD labs as one track. The payloads are short; the value is a mental model and a set of operational details the official solutions skip.

## The three axes

Every WCD lab is a point in a three-dimensional space:

1. **What makes the cache store the response?** A file extension (`.js`), a static-directory prefix (`/resources/*`), or an exact filename (`/robots.txt`).
2. **Who normalizes the path — the origin or the cache?** This decides the *direction* of the payload.
3. **Which delimiter truncates the origin back to the sensitive endpoint?** `;`, `%23`, etc. (never a raw `#` — the browser eats it as a fragment before the request leaves).

| Lab | Cache rule | Normalizer | Crafted URL |
|-----|-----------|-----------|-------------|
| path mapping | `.js` extension | — (path mapping) | `/my-account/wcd.js` |
| path delimiters | `.js` extension | — (`;` delimiter) | `/my-account;wcd.js` |
| origin normalization | `/resources/*` | **origin** | `/resources/..%2fmy-account` |
| cache server normalization | `/resources/*` | **cache** | `/my-account%23%2f%2e%2e%2fresources` |
| exact-match rules | `/robots.txt` | **cache** | `/my-account;%2f%2e%2e%2frobots.txt` |

The mirror pair is the instructive one. When the **origin** normalizes (lab 3), you put the dot-segment *after* the static prefix and let the origin resolve it back to the dynamic page. When the **cache** normalizes (labs 4-5), you put the dot-segment *after* the dynamic path and let the cache resolve it *down to* the static target. Same trick, opposite directions, because a different party is doing the resolving.

## From reading data to changing it

Labs 1-4 read carlos's API key. Lab 5 (Expert) is the interesting escalation: the cached page is the **administrator's** `/my-account`, which contains a CSRF token. So the chain becomes:

1. WCD-cache the admin's account page; read the admin's CSRF token from it.
2. Deliver an auto-submitting form that POSTs `/my-account/change-email` with that token.

WCD stops being an information leak and becomes a state-changing CSRF primitive. Any cached authenticated page that contains a token or a nonce is a candidate.

## The operational details the solution omits

Automating this surfaced a few things no walkthrough mentions:

- **The `302 → /login` is cached too.** The cache stores by extension/prefix regardless of status code. If you fetch the crafted URL *before* the victim, you cache the login redirect and permanently block their page from being stored. Self-poisoning. Use a fresh cache-buster every attempt and never fetch first.
- **There is a grab race.** After the victim loads your exploit page, their browser's request to the crafted URL lands ~1-2 seconds later. If you fetch the instant you see the victim hit the exploit server, you cache the `302` ahead of them. The fix is unglamorous: **wait a few seconds after detecting the victim, then fetch.** This one cost me a lab until I added the delay.
- **Don't poll the crafted URL to detect success** — that's the poisoning move. Poll the *exploit server access log* for the victim's user-agent instead; it doesn't touch the crafted-URL cache.
- **A raw `#` is useless as a delimiter** (fragment), but `%23` survives into the request.
- **Client tools collapse `../`.** Send the encoded dot-segments with path normalization disabled, or the payload never reaches the server intact.

## Defender notes

The root fix is boring and absolute: **the cache and origin must parse and normalize paths identically, the cache key must be the fully normalized path, and authenticated/dynamic responses must never be cached** (`Cache-Control: no-store`, and skip anything with `Set-Cookie`). Crucially, don't decide cacheability from the URL's *shape* — extension, prefix, filename — decide it from the origin's actual `Content-Type` and cache headers.

For detection: a `text/html` response served under a static cache rule is the canonical tell; so is the same "static" URL returning different per-user content (different keys, usernames, CSRF tokens). And watch for a sensitive write like `POST /my-account/change-email` arriving on the heels of a WCD-shaped cached fetch — that's the CSRF chain.

Five labs, one sentence: **exploitation lives in the gap between two parsers, and so does the fix.**
