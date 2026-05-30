---
layout: post
title: "Business Logic Bugs Are Broken Invariants"
date: 2026-06-27 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [business-logic, state-machine, parser-discrepancy, portswigger]
related_posts:
  - authentication-bugs-are-state-machine-bugs
  - authorization-is-not-a-route-name
  - information-leaks-are-missing-exploit-parameters
---

Business logic bugs rarely look like classic injection. The payload may be a negative number, a missing parameter, a replayed confirmation URL, or an email address that two parsers disagree about.

The invariant is the target.

## Ask what must never be false

Across the twelve PortSwigger labs, the broken invariants are plain:

- product price must come from the catalog;
- quantity must be positive and bounded;
- coupons must be unique per order;
- account roles must not depend on editable email state;
- password changes must bind to the authenticated subject;
- order confirmation must require paid checkout;
- login state must not default to admin;
- encrypted cookies must not be forgeable through another feature;
- email validation and delivery must use the same canonical address.

Once written this way, each lab becomes a search for where the application forgot to enforce the rule.

The series was re-run and live-verified on 2026-05-30 as 12/12 solved. The
gift-card lab is a useful reminder that observability matters: the profitable
codes were delivered through the Academy email client, not the order page.

## Money bugs are boundary bugs

The early shopping labs are variations on server-side authority.

If `POST /cart` accepts `price`, the user can set the price. If `quantity` accepts negative values, a cheap product can offset an expensive one. If totals can overflow, enough additions can wrap the balance into a buyable range.

The infinite-money lab is the same family at a workflow level:

```text
buy $10 gift card with 30% discount -> pay $7 -> redeem $10 -> profit $3
```

Automation does not create the bug. It only repeats the economic invariant failure.

## Inconsistency creates privilege

Several labs are not about one vulnerable endpoint. They are about two endpoints enforcing different versions of the same rule.

Registration validates one email state. Email-change updates another. Authorization later trusts the updated domain.

Password change is even cleaner: a self-service endpoint and an administrative endpoint collapse into one parameter-driven action. Remove `current-password`, set `username=administrator`, and the endpoint changes someone else's password.

The fix is not scattered input filtering. The fix is a shared rule and an explicit subject/action/resource authorization check.

## Workflows must validate every step

Multi-step flows fail when the final step assumes all earlier steps happened correctly.

Replaying:

```http
GET /cart/order-confirmation?order-confirmation=true
```

after adding a new expensive item should not complete the order. Confirmation must re-check payment state, basket contents, and balance.

Login state machines have the same issue. Dropping the role-selection request should not leave the session in a privileged default state.

## Oracles and parsers are business logic too

The encryption-oracle lab combines two harmless-looking features: one encrypts a user-controlled notification, another decrypts and reflects it. Together, they forge a remember-me cookie.

The expert email lab is a parser discrepancy. Validation sees the approved domain; the mailer decodes UTF-7 encoded-word content and sends the confirmation elsewhere.

Complex formats need one canonical parser. Multiple parsers are multiple security decisions.

## Defender notes

Hardening:

- calculate price, discounts, role, balance, and identity server-side;
- reject negative, zero, huge, and overflowing numeric inputs;
- centralize business rules used by multiple endpoints;
- validate every workflow step independently;
- split self-service and administrative endpoints, or enforce explicit authorization on both;
- fail closed when a state machine is interrupted;
- context-bind encrypted cookies and avoid reusable oracles;
- use one canonical parser for email and other complex standards.

Detection:

- client changes to `price`, `quantity`, `discount`, `username`, `role`, or `email`;
- negative quantities, huge quantities, repeated coupon alternation;
- password changes missing `current-password`;
- direct order-confirmation replay;
- login sessions that skip role selection;
- repeated gift-card buy/redeem loops;
- encoded-word, UTF-7, multiple-`@`, or unusually long email registrations.

Business logic testing is not a grab bag of tricks. It is invariant testing: write down what must be true, then try every endpoint and transition that can make it false.
