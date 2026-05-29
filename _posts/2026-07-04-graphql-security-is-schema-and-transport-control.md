---
layout: post
title: "GraphQL Security Is Schema and Transport Control"
date: 2026-07-04 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [graphql, api-security, csrf, portswigger]
related_posts:
  - prototype-pollution-is-property-lookup-abuse
  - targeted-scanning-is-a-manual-testing-tool
  - authentication-bugs-are-state-machine-bugs
---

GraphQL concentrates an application's API surface behind one endpoint. That does not reduce the number of security boundaries. It hides them inside schema, resolver, and transport behavior.

The PortSwigger GraphQL labs are a compact reminder: the dangerous question is not only "where is the endpoint?" It is "what can this principal ask for, how many times, and through which browser mechanics?"

## Schema is reconnaissance

Introspection turns the API into a map:

```graphql
{ __schema { types { name fields { name } } } }
```

If private fields such as passwords, tokens, or hidden post metadata appear in the schema and resolvers do not enforce authorization, the client can simply ask for them.

Hiding the field in the UI is not a control. Resolver authorization is the control.

## Hidden endpoints still answer universal queries

A useful endpoint probe is:

```graphql
query { __typename }
```

If `/api?query=query{__typename}` returns a type name, you found a GraphQL endpoint even if navigation never referenced it.

Blocking introspection with a string match is brittle. A filter looking for `__schema{` can miss valid GraphQL with whitespace:

```graphql
query {
  __schema
  {
    queryType { name }
  }
}
```

GraphQL should be parsed and authorized, not filtered with raw-string assumptions.

## Execution semantics affect rate limits

Aliases let one operation run many sibling fields or mutations:

```graphql
mutation {
  a: login(input: {username: "carlos", password: "123456"}) { success }
  b: login(input: {username: "carlos", password: "password"}) { success }
}
```

A limiter that counts one HTTP request misses the fact that many login attempts happened inside that request. API controls have to count semantic actions, not just network envelopes.

## Transport can create CSRF

GraphQL is often shown as JSON over POST. Some endpoints also accept form-urlencoded bodies:

```text
query=...&operationName=changeEmail&variables=...
```

That can turn a mutation into a browser simple request, allowing a cross-site form POST with ambient cookies. State-changing GraphQL operations need CSRF protection and strict content-type policy.

## Defender notes

Hardening:

- disable or authenticate introspection;
- enforce authorization inside resolvers for fields and objects;
- treat ids as object references requiring ownership checks;
- reject regex-only introspection filters;
- restrict aliases and batching for sensitive mutations;
- rate-limit by action count, username, account, and IP;
- require JSON and CSRF tokens for state changes;
- reject GET for mutations.

Detection:

- introspection terms with unusual whitespace or encoding;
- many aliases calling the same mutation;
- GraphQL query strings on unexpected paths;
- low-privilege users requesting credential-like fields;
- form-urlencoded traffic to GraphQL endpoints;
- state-changing mutations without CSRF signals.

GraphQL's power is legitimate. The mistake is letting the schema, resolver layer, and browser transport rules drift out of the threat model.
