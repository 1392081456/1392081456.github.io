---
layout: post
title: "Authorization Is Not a Route Name"
date: 2026-06-21 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [access-control, idor, portswigger, authorization]
related_posts:
  - csrf-tokens-do-not-prove-user-intent
  - request-smuggling-is-a-parser-disagreement
  - cors-is-not-authorization
---

Access control bugs are rarely subtle at the model level. They come from trusting the wrong thing.

The 13 PortSwigger access control labs make the pattern clear:

**Authorization must be enforced by the server on the resource and action being performed.**

Everything else is a hint, not an authority.

## The map

| Trust mistake | Example |
|---------------|---------|
| hidden route | admin path in `robots.txt` or JavaScript |
| client role | `Admin=true` cookie |
| mass assignment | JSON body accepts `roleid: 2` |
| object identifier | `id=carlos` |
| unpredictable identifier | GUID leaked elsewhere |
| redirect behavior | 302 body still contains account data |
| method split | POST blocked, GET allowed |
| workflow split | confirmation step lacks auth |
| header trust | Referer treated as permission |

## Hidden is not authorized

The first labs expose admin functionality through `robots.txt` or JavaScript. The admin route may be obscure, but it is still unauthenticated.

This distinction matters in real systems. Discovery controls can reduce noise. They cannot decide whether a user may delete an account.

## The client cannot assign its role

Two labs trust client-controlled privilege state:

```http
Admin=true
```

and:

```json
{"roleid": 2}
```

Both are the same class of bug. The client is allowed to define a server-side authorization fact.

The fix is not "hide the field." The fix is DTO allowlisting and server-side privilege state.

## IDOR is about ownership

The basic horizontal escalation is:

```http
/my-account?id=carlos
```

The GUID version only changes enumeration. Carlos's GUID appears in a blog author link, so the account endpoint is still missing an ownership check.

Redirect leakage is another version of the same mistake. The app sends a 302 away from Carlos's page, but the 302 body still contains his API key. Automatic redirect following can hide the vulnerable response during manual testing.

The transcript lab reduces this to a filesystem object reference: `1.txt` contains another user's chat log and password.

The invariant is owner/resource/action. Every object access needs it.

## Routes, methods, and workflows must agree

Front-end URL blocking fails when the back end honors a different route source:

```http
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

The front end authorizes `/`; the back end executes `/admin/delete`.

Method-based checks fail when POST is protected but GET reaches the state-changing action:

```http
GET /admin-roles?username=wiener&action=upgrade
```

Multi-step workflows fail when only the first step checks admin rights. Referer-based checks fail because Referer is just a request header.

## Defender notes

Hardening:

- enforce authorization on every sensitive server-side handler;
- base decisions on server-side session and permission models;
- never trust client-supplied role, owner, admin, or user ID fields;
- use DTO allowlists for profile/account updates;
- check subject, action, and resource for every object access;
- treat GUIDs as identifiers, not permissions;
- avoid sensitive data in redirect bodies and error responses;
- validate every step in multi-step workflows;
- apply the same authorization policy across methods;
- disable or tightly constrain route override headers;
- never use Referer as authorization.

Detection:

- normal users requesting `/admin`, `/administrator-panel`, `/admin-roles`, or delete routes;
- client requests containing `Admin=true`, `roleid`, `isAdmin`, or unexpected owner fields;
- one session iterating user IDs, GUIDs, filenames, or transcript numbers;
- 302 responses containing API keys, passwords, or account details;
- state-changing GET requests;
- non-admin sessions carrying admin Referer headers;
- `X-Original-URL` and similar override headers.

The practical rule is simple: authorize the final action where it happens. Do not outsource authorization to route obscurity, browser behavior, request headers, or client-controlled state.
