---
layout: post
title: "XSS Is a Parser Boundary Problem - A Thirty-Lab Map"
date: 2026-06-13 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [xss, portswigger, dom-xss, angularjs, csp, browser-security]
related_posts:
  - csrf-tokens-do-not-prove-user-intent
  - ssrf-is-a-network-position-bug
  - entity-resolution-is-a-file-and-network-boundary
---

Cross-site scripting is often taught as "inject `<script>alert(1)</script>`." That is a useful first proof, but it is not the skill.

The skill is context recognition.

**XSS is a parser boundary problem.** The same bytes mean different things in HTML text, an HTML attribute, a JavaScript string, a template literal, a URL, an SVG subtree, an AngularJS expression, a DOM sink, or a CSP-controlled page. A defense that is correct for one context can be irrelevant in another.

The thirty PortSwigger XSS labs are a good map of that boundary.

## The map

| Lab group | Context | Main question |
|-----------|---------|---------------|
| basic reflected/stored | HTML body and comments | is output encoded at all? |
| DOM sinks | `document.write`, `innerHTML`, jQuery `href`, jQuery selector | which browser API turns data into markup, URL, or selector? |
| attribute and script contexts | HTML attributes, JavaScript strings, template literals | which parser can I exit? |
| filtered markup | tag/attribute allowlists, custom elements, SVG, canonical link | which browser features are still reachable? |
| framework contexts | AngularJS expressions and sandbox escapes | is this a template execution environment? |
| impact labs | cookie, password, CSRF token | what can the victim browser do with its current session? |
| CSP labs | strict policy, dangling markup, reflected CSP token | can I avoid script, or can I change the policy itself? |

That table is the workflow: identify the context first, then pick the smallest parser-specific escape.

## HTML is only the first context

The opening labs are intentionally plain:

```html
<script>alert(1)</script>
```

That proves unencoded HTML output. Stored XSS is the same primitive with persistence: put the script in a comment and wait for the victim view.

The moment the input moves into an attribute or a JavaScript string, the payload changes. If angle brackets are encoded but the input sits in an attribute, a tag is the wrong tool:

```text
"onmouseover="alert(1)
```

If the input sits inside a JavaScript string, the correct exit depends on quote and backslash handling:

```text
'-alert(1)-'
\\'-alert(1)//
</script><script>alert(1)</script>
```

That last one is the reminder many filters miss: the HTML parser recognizes `</script>` as the end of the script element before JavaScript string semantics can save you.

Template literals add another rule. If backticks and quotes are escaped but interpolation remains available:

```text
${alert(1)}
```

the payload never needs to close the template.

## DOM XSS means read the client code

DOM labs are not solved by staring at the server response. The sink is in the JavaScript.

`document.write` inside an HTML attribute can be escaped with:

```text
"><svg onload=alert(1)>
```

If the write happens inside a `select`, the payload first exits that parser state:

```text
"></select><img src=1 onerror=alert(1)>
```

For `innerHTML`, injected `<script>` tags are not the stable path. Event-bearing elements are:

```html
<img src=1 onerror=alert(1)>
```

jQuery can create different bug classes depending on the API. Setting `href` makes a URL sink:

```text
/feedback?returnPath=javascript:alert(document.cookie)
```

Selector construction makes a selector sink, where a hashchange can become markup when the selector parser is confused.

## Filters leave browser features behind

The filtered labs are not about memorizing exotic tags. They are about enumerating what the browser can still do after the filter has removed the obvious path.

If most tags and attributes are blocked, an allowed `body onresize` pair can still execute when an iframe changes size. If all standard tags are blocked, a custom element with `tabindex` and `onfocus` can run when the fragment targets it:

```html
<xss id=x onfocus=alert(document.cookie) tabindex=1>
```

SVG has its own event and animation surface:

```html
<svg><animatetransform onbegin=alert(1)>
```

and even when event handlers and `href` attributes are blocked, SVG animation can assign a `javascript:` URL at runtime:

```html
<svg><a><animate attributeName=href values=javascript:alert(1) />
```

The defensive mistake is treating HTML as a single feature. It is a large runtime.

## Framework expressions are execution surfaces

AngularJS expression contexts are not fixed by encoding `<` and `>`.

The simple expression escape reaches a constructor:

{% raw %}
```text
{{$on.constructor('alert(1)')()}}
```
{% endraw %}

The harder variants remove strings or add CSP. Then the route shifts to prototype mutation, filters, and event objects:

```text
ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'
```

The broader lesson applies beyond AngularJS: if user input reaches a template expression language, you are no longer only defending HTML. You are defending an execution engine.

## Impact is same-origin power

The most useful labs are the impact labs, because they show why "it only runs in the browser" is not a comfort.

In the cookie lab, a stored script can post `document.cookie` back into the same blog comments and then use the captured session to visit `/my-account`.

In the password lab, I avoided an external Collaborator dependency by using the application itself as the collection channel. The payload adds username and password fields, waits for the victim password manager to fill them, and writes the result back to the same post as a comment.

In the CSRF lab, the script does not need to steal anything. It reads `/my-account` in the victim session, extracts the CSRF token, and posts the protected email-change form:

```js
var req = new XMLHttpRequest();
req.onload = function() {
  var token = this.responseText.match(/name="csrf" value="([^"]+)"/)[1];
  var r = new XMLHttpRequest();
  r.open('POST', '/my-account/change-email', true);
  r.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  r.send('csrf=' + encodeURIComponent(token) + '&email=xss24@example.net');
};
req.open('GET', '/my-account', true);
req.send();
```

This is why CSRF defenses are not a substitute for XSS prevention. XSS runs on the right origin, with the right cookies, and can often read the right token.

## CSP changes the shape, not the need for context control

Strict CSP can block inline script, but it does not make arbitrary HTML injection safe.

The dangling-markup lab uses form flow instead of script: inject a button whose `formaction` sends the victim token to an attacker-controlled page, then auto-submit the final state-changing request from there.

The final lab is even more direct: user input is reflected into the CSP token itself. That turns the security policy into another injection context:

```text
?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

CSP is a valuable mitigation, but it must be generated from constants and reviewed like code.

## Defender notes

The best XSS defense starts with exact context ownership:

- encode for the exact output context: HTML text, attribute, JavaScript string, URL, CSS, and JSON are different sinks;
- avoid dangerous DOM APIs for untrusted input: `innerHTML`, `document.write`, selector construction, and URL-bearing attributes;
- use a mature sanitizer for rich text, then keep sanitized HTML out of JavaScript and URL contexts;
- set cookies `HttpOnly`, `Secure`, and `SameSite`, while remembering that XSS can still perform same-origin actions;
- bind CSRF tokens to session, path, method, and lifetime, but do not expect CSRF to survive XSS;
- build CSP headers from constants, preferably with nonces or hashes;
- retire legacy expression surfaces such as AngularJS where possible.

Detection should look for behavior, not only payload strings:

- user-controlled fields containing event attributes, `javascript:`, SVG animation, Angular expressions, or template interpolation;
- page loads followed by unexpected XHR/fetch to comment, account, or email-change endpoints;
- comments containing session-like values or credential-shaped pairs posted by privileged or victim user agents;
- CSP reports for inline script, blocked `javascript:` URLs, or unusual form-action targets;
- account changes immediately after a victim views a comment page.

The durable rule is simple: XSS is not one filter failure. It is a family of parser-boundary failures, and every browser context deserves its own control.
