---
layout: post
title: "CSRF Tokens Do Not Prove User Intent - A Clickjacking Methodology"
date: 2026-06-10 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [clickjacking, csrf, ui-redressing, portswigger, browser-security]
related_posts:
  - web-cache-deception-five-labs
  - 18-sqli-labs-from-tautologies-to-oob
---

The five PortSwigger clickjacking labs are short, but they make one point that is easy to forget during web reviews:

**A CSRF token proves that a request came from the real page. It does not prove that the user understood what they clicked.**

Clickjacking does not forge the HTTP request. It forges the visual context around the user's click. The browser still sends the victim's cookies. The target page still submits its own CSRF token. The broken assumption is user intent.

## The boundary shift

Most request-forgery bugs are about constructing a request the victim did not mean to send. Clickjacking is different. The attacker lets the victim load the legitimate page, then places that page in a transparent frame and aligns a decoy prompt over the real button.

The browser sees a normal interaction:

```text
victim click -> transparent iframe -> real form -> victim cookies + real CSRF token
```

The user sees something else.

That is why a CSRF-protected delete form can still be clickjacked. The token is valid because the framed page generated it. The security decision that failed happened one layer earlier: the sensitive page was allowed to enter an attacker-controlled visual context.

## The five-lab map

The labs form a clean progression:

| Lab | Target action | Framed URL | Lesson |
|-----|---------------|------------|--------|
| basic clickjacking | delete account | `/my-account` | CSRF tokens do not stop a real framed form submission |
| URL-prefilled form | change email | `/my-account?email=...` | prefilled state reduces the victim's work to one click |
| frame buster script | change email | sandboxed account page | script frame-busters are not a security boundary |
| DOM XSS trigger | call `print()` | prefilled feedback form | clickjacking can be a trigger for a separate client-side sink |
| multistep flow | delete + confirm | account page | confirmations are also frameable unless protected |

The interesting part is not the CSS. It is the repeated pattern: the target action already exists in the legitimate UI, so the attacker only has to make a real user gesture land on it.

## The basic shape

The standard lab page has three layers:

```html
<style>
iframe {
  position: relative;
  width: 500px;
  height: 700px;
  opacity: 0.0001;
  z-index: 2;
}
.decoy {
  position: absolute;
  top: 498px;
  left: 70px;
  z-index: 1;
}
</style>
<div class="decoy">Click me</div>
<iframe src="https://LAB.web-security-academy.net/my-account"></iframe>
```

The decoy text is visually below the iframe. The click lands on the transparent framed page above it. During testing, setting `opacity: 0.1` makes alignment visible; before delivery, the frame is made effectively invisible.

The practical trap is coordinate space. The relevant coordinates are not the outer browser window coordinates. They are the target button's coordinates inside the iframe viewport. A `500x700` iframe and an `800x600` tab do not produce the same layout.

A simple alignment probe is:

```js
const el = [...document.querySelectorAll("button")]
  .find(b => /Update email|Delete account|Yes|Submit feedback/.test(b.textContent));
el.getBoundingClientRect();
```

Set the browser viewport to match the iframe dimensions before using the result.

## Prefill turns forms into buttons

The second lab is useful because it shows how clickjacking combines with harmless-looking state prefill. If `/my-account?email=attacker@example.net` populates the email field, the victim no longer needs to type anything. The only remaining gesture is the click on `Update email`.

That is not a form-validation bypass. It is workflow compression.

Any sensitive form that can be pre-populated through a URL parameter, fragment, saved state, or client-side routing state becomes easier to clickjack. The attacker does not need to simulate a complete user session; they only need to line up the final confirmation gesture.

## Script frame-busters are not controls

One lab includes a JavaScript frame-buster. The workaround is a sandboxed iframe:

```html
<iframe
  sandbox="allow-forms"
  src="https://LAB.web-security-academy.net/my-account?email=attacker@example.net">
</iframe>
```

`allow-forms` keeps form submission working. Omitting `allow-scripts` prevents the frame-buster script from running.

This is why frame-busting JavaScript is not a reliable security boundary. The control must be delivered in headers, before the page executes inside the attacker's document:

```http
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY
```

Use `frame-ancestors` as the primary control; keep `X-Frame-Options` for legacy coverage.

## Clickjacking as a trigger, not the whole bug

The DOM XSS lab is the most useful from a threat-modeling point of view. The clickjacking layer only triggers the feedback form. The execution happens later when the page renders attacker-controlled feedback data into a DOM sink.

The chain looks like this:

```text
URL prefill -> victim clicks Submit feedback -> result renderer writes name -> XSS fires
```

That pattern generalizes. Clickjacking often does not need to be the final vulnerability. It can be the user-interaction primitive that activates another bug:

- submit a form that reaches a stored or reflected XSS sink;
- click an OAuth consent button;
- accept a browser permission prompt;
- approve a destructive workflow;
- confirm a dangerous setting change.

If a client-side bug requires a trusted user's click, clickjacking is one way to supply it.

## Multistep flows are not automatically safe

The final lab adds a confirmation button. That changes the payload from one aligned click to two aligned clicks. It does not change the root issue.

Two-step delete flow:

```text
click 1: Delete account
click 2: Yes
```

The second page is still part of the framed flow, so the second click can also be aligned. A confirmation page is useful only if the confirmation step is resistant to framing or requires interaction that cannot be delegated by one or two blind clicks.

Better confirmations include:

- re-authentication;
- WebAuthn or OTP;
- a typed confirmation phrase for destructive actions;
- a server-side risk challenge after sensitive state changes;
- frame protection on every page in the workflow.

The last point matters. Protecting only the first page is not enough if a later confirmation endpoint remains frameable.

## Detection ideas

Clickjacking detection is harder than SQL injection detection because the malicious bytes often live on a different origin. Still, there are useful signals.

On the web edge or application side:

- sensitive endpoints framed by unexpected `Referer` or `Sec-Fetch-Site` contexts;
- account changes with little or no normal navigation history;
- short mechanical sequences such as `GET /my-account` followed immediately by `POST /my-account/delete`;
- sensitive POSTs where the user did not recently interact with the visible top-level site;
- spikes in destructive actions after visits from external pages.

On pages you crawl or collect during abuse investigations:

- transparent or near-transparent iframes targeting account, settings, payment, or feedback pages;
- CSS combinations such as `opacity: 0.0001`, absolute-positioned decoys, and layered `z-index`;
- sandboxed iframes with `allow-forms` but not `allow-scripts`;
- lure text near coordinates that match real buttons inside the frame.

For modern browser telemetry, `Sec-Fetch-Site`, `Sec-Fetch-Dest`, `Origin`, and `Referer` are useful but not sufficient. The robust fix is still to keep sensitive pages out of hostile frames.

## Defender checklist

For account settings, payments, admin consoles, and destructive workflows:

1. Set `Content-Security-Policy: frame-ancestors 'none'` or a strict allowlist.
2. Add `X-Frame-Options: DENY` or `SAMEORIGIN` for legacy clients.
3. Do not rely on JavaScript frame-busters.
4. Avoid URL-prefilling sensitive final-state forms, or require visible confirmation after prefill.
5. Treat every step of a confirmation flow as a frameable attack surface.
6. Require stronger user intent for destructive actions: re-authentication, typed confirmation, or phishing-resistant MFA.
7. Log and review sensitive actions with cross-site framing indicators and abnormal dwell time.

## Closing thought

Clickjacking is not a bypass of CSRF tokens. It is a reminder that CSRF tokens answer the wrong question for this class of bug.

They answer: did the request come from the real page?

Clickjacking asks: did the user know what page they were interacting with?

Those are different security properties. The fix has to live at the visual-context boundary: do not let sensitive pages run inside frames controlled by someone else.
