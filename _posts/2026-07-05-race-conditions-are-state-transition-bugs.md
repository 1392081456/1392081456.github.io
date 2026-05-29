---
layout: post
title: "Race Conditions Are State Transition Bugs"
date: 2026-07-05 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [race-conditions, business-logic, turbo-intruder, portswigger]
related_posts:
  - graphql-security-is-schema-and-transport-control
  - business-logic-bugs-are-broken-invariants
  - file-upload-is-a-four-stage-boundary
---

Race conditions are often described as "send requests at the same time." That is the delivery technique, not the bug.

The bug is a non-atomic state transition. The application checks one state, acts later, and leaves a window where another request can change what the first request thought it had validated.

## Find the transition first

The PortSwigger race-condition labs cover the usual targets:

- coupon use;
- login failure counters;
- checkout validation;
- pending email changes;
- password-reset tokens;
- registration confirmation.

Each one has a state transition. The useful test is to split it into check, write, confirmation, and side effect. The race window usually lives between two of those steps.

## Same endpoint, different endpoint, or side effect

Some races repeat one request:

```text
POST /cart/coupon
```

Others line up different requests:

```text
POST /cart
POST /cart/checkout
```

The email-change lab shows a third form: the bug is not the endpoint itself, but an asynchronous side effect. The database says one pending email while the mail-rendering task reads another.

That distinction matters for testing. Replaying one request is not enough; you have to understand the workflow.

## Precision beats volume

Volume helps only if requests actually hit the window. HTTP/2 single-packet attacks and gate-based release make timing sharper:

```python
for payload in payloads:
    engine.queue(target.req, payload, gate='1')
engine.openGate('1')
```

The goal is not just "many requests." It is "the server observes the same stale state many times."

## Partial construction is the dangerous edge

The expert lab is a partial-construction bug. A user is partly created before its confirmation token is fully initialized. A confirmation request using an empty-array token shape can land in that temporary state:

```http
POST /confirm?token[]=
```

This class appears whenever systems expose half-built rows, files, sessions, or jobs to other endpoints.

## Defender notes

Hardening:

- put check-and-act logic in transactions or atomic operations;
- use row locks, unique constraints, and compare-and-set for shared state;
- make coupons, balances, counters, and pending-email records single-owner transitions;
- bind async jobs to immutable snapshots;
- generate reset tokens with CSPRNGs, not timestamps;
- keep partial objects invisible until fully initialized;
- serialize critical actions per user or resource.

Detection:

- bursts of identical state-changing requests;
- impossible counts, such as multiple coupon successes;
- lockout counters lower than the observed attempts;
- order success after insufficient-funds responses;
- mismatched email recipient and confirmation body;
- duplicated reset tokens;
- empty-array or malformed confirmation tokens.

Good race-condition defense is not "hope requests arrive slowly." It is making the state transition indivisible.
