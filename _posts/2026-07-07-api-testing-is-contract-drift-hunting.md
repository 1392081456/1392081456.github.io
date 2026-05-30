---
layout: post
title: "API Testing Is Contract Drift Hunting"
date: 2026-07-07 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [api-security, mass-assignment, parameter-pollution, portswigger]
related_posts:
  - nosql-injection-is-query-shape-injection
  - graphql-security-is-schema-and-transport-control
  - authorization-is-not-a-route-name
---

API bugs often come from contract drift. The frontend shows one contract; the backend accepts a wider one.

The PortSwigger API Testing labs cover the usual drift points: documentation, methods, hidden fields, query strings, and REST paths.

## Start from the real traffic

A visible request such as:

```http
PATCH /api/user/wiener
```

is a map. Walk upward to `/api/user`, then `/api`. Try documentation paths. If interactive docs are exposed to ordinary users, the hidden contract may include administrative operations.

## Methods are part of authorization

A product page may only issue:

```http
GET /api/products/1/price
```

but `OPTIONS` can reveal:

```text
GET, PATCH
```

If `PATCH` accepts:

```json
{"price":0}
```

then the frontend hid an update method that the backend failed to authorize.

## Response fields are not write fields

Mass assignment starts with a diff. If GET returns:

```json
"chosen_discount": {"percentage": 0}
```

and POST does not normally send it, test whether POST accepts it anyway. A 100% discount should be server-controlled, not a client-supplied field.

## Internal URL building is a parser boundary

Server-side parameter pollution appears when input is concatenated into an internal request:

```text
username=administrator%26field=reset_token%23
```

For REST paths, the same issue becomes path pollution:

```text
username=../../v1/users/administrator/field/passwordResetToken%23
```

The bug is not the encoded character itself. The bug is building internal URLs by string concatenation and letting user input become query or path syntax.

## Defender notes

Hardening:

- authenticate documentation and OpenAPI endpoints;
- authorize every HTTP method independently;
- use structured URL builders for internal requests;
- normalize and allowlist path segments;
- use write DTOs instead of binding request JSON to domain objects;
- keep price, discount, role, and token fields server-owned;
- make error messages useful for operators, not endpoint discovery.

Detection:

- user traffic to docs and API definition files;
- encoded separators in username or id parameters;
- unexpected `OPTIONS`, `PATCH`, `PUT`, or `DELETE`;
- clients submitting response-only fields;
- reset flows probing arbitrary field names;
- traversal sequences inside API path parameters.

API testing is contract drift hunting: find what the backend really accepts, then decide whether the current user should ever have been allowed to send it.
