---
layout: post
title: "Prototype Pollution Is Property Lookup Abuse"
date: 2026-07-03 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [prototype-pollution, nodejs, dom-xss, portswigger]
related_posts:
  - targeted-scanning-is-a-manual-testing-tool
  - jwt-security-is-verification-policy
  - deserialization-restores-code-paths
---

Prototype pollution is often described as a write bug: get `__proto__` into a parser, write to `Object.prototype`, win.

That is only the primitive. The impact is a read bug. Some later code looks for an own property, does not find one, and silently accepts the inherited value.

The PortSwigger prototype pollution labs are useful because they separate those two halves.

## The chain has three parts

A real chain needs:

- a source that writes to the prototype;
- a gadget that reads a missing property;
- a sink that treats the inherited value as code, configuration, or authority.

Client-side examples include dynamic script URLs and `eval()`:

```text
?__proto__[transport_url]=data:,alert(1);
```

Server-side examples include authorization flags and child process options:

```json
{"__proto__":{"isAdmin":true}}
```

The same pollution source can be harmless or critical depending on what property the application reads later.

## Sanitizers fail when they are not parsers

One lab uses a one-pass key sanitizer. Splitting the forbidden key is enough:

```text
?__pro__proto__to__[transport_url]=data:,alert(1);
```

Another blocks `__proto__` but misses the equivalent object path:

```json
{"constructor":{"prototype":{"isAdmin":true}}}
```

Prototype pollution filters need recursive structural validation. A blacklist applied once to a raw string is not enough.

## Non-reflective detection matters

Server-side pollution may not reflect arbitrary properties. That does not mean it failed.

One safer probe is to pollute a status-code property, then trigger a controlled parse error:

```json
{"__proto__":{"status":555}}
```

If the error object changes status, the prototype was modified without needing destructive impact. Similar low-impact probes include JSON spacing and charset behavior.

## Child process gadgets are configuration bugs

The later labs show why inherited options are dangerous. If a maintenance job spawns a Node child process, inherited `execArgv` can add runtime flags. If code passes an options object to `execSync()`, inherited `shell` and `input` can control execution behavior.

The fix is not just filtering request keys. Sensitive option objects should be constructed explicitly and should not inherit attacker-controlled prototype state.

## Defender notes

Hardening:

- reject `__proto__`, `constructor`, and `prototype` recursively;
- use `Object.create(null)` for merge targets and option objects;
- check authorization with own properties only;
- avoid string-based JavaScript sinks;
- construct child process options from known fields only;
- test `--disable-proto=throw` in Node deployments;
- keep parser and merge libraries current.

Detection:

- prototype-key strings in query, fragment, JSON, or cookie data;
- split-key variants that reconstruct dangerous names;
- JSON spacing, error status, or charset changes after profile updates;
- ordinary users seeing admin-only links;
- maintenance jobs failing after account-data writes;
- unexpected `--eval`, shell, or input options in spawned processes.

The core defensive question is simple: can this object read inherited authority or configuration? If yes, a parser bug can become a system bug.
