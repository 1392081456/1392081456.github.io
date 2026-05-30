---
layout: post
title: "NoSQL Injection Is Query Shape Injection"
date: 2026-07-06 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [nosql-injection, mongodb, authentication, portswigger]
related_posts:
  - race-conditions-are-state-transition-bugs
  - graphql-security-is-schema-and-transport-control
  - authentication-bugs-are-state-machine-bugs
---

NoSQL injection is not just "SQL injection but without SQL." The common failure is that user input changes the shape of the query.

In the PortSwigger NoSQL labs, a string becomes JavaScript, a scalar becomes a MongoDB operator, and hidden document fields become enumerable through `$where`.

## Strings become expressions

A category filter should treat input as data. If it is interpolated into a JavaScript-style condition, syntax and boolean probes reveal the boundary:

```text
Gifts' && 0 && 'x
Gifts' && 1 && 'x
```

An always-true expression widens the result set:

```text
Gifts'||1||'
```

That is not a category value anymore. It is query logic.

## Scalars become operators

JSON APIs make operator injection easy to miss. The client is expected to send:

```json
{"username":"wiener","password":"peter"}
```

but the server accepts:

```json
{"username":{"$regex":"admin.*"},"password":{"$ne":""}}
```

The field that should be a string becomes a query object. Schema validation should reject that before the database driver sees it.

## `$where` turns documents into an oracle

If `$where` is accepted, JavaScript can inspect the current document:

```json
{"$where":"this.password[0]=='a'"}
```

Response differences become a boolean oracle for passwords, reset tokens, and even unknown field names:

```json
{"$where":"Object.keys(this)[1].match('^.{0}u.*')"}
```

The database is no longer just filtering rows. It is evaluating attacker-controlled code over user objects.

## Defender notes

Hardening:

- enforce JSON schemas at the API boundary;
- reject objects where scalar strings are expected;
- deny operator keys in user-controlled input;
- construct query objects from allowlisted fields;
- disable `$where` and server-side JavaScript;
- keep reset tokens and credential fields out of user-facing query surfaces;
- normalize login and reset error messages.

Detection:

- `$ne`, `$regex`, `$where`, `Object.keys(this)`, or `this.password`;
- quote-plus-boolean probes in query strings;
- login parameters changing type from string to object;
- character-position enumeration patterns;
- reset endpoints probed with unusual token field names.

The boundary is the query shape. Once the attacker controls that shape, the database becomes an execution and enumeration engine.
