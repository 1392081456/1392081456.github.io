---
layout: post
title: "Path Traversal Is a Canonicalization Bug"
date: 2026-06-20 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [path-traversal, file-read, portswigger, canonicalization]
related_posts:
  - ssti-is-context-first
  - ssrf-is-a-network-position-bug
  - request-smuggling-is-a-parser-disagreement
---

Path traversal is often described as "put `../` in the filename." That is the first lab, not the model.

The model is:

**The string you validate is not necessarily the path the filesystem opens.**

The six PortSwigger path traversal labs are a compact tour of canonicalization mistakes: raw traversal, absolute paths, non-recursive stripping, double decoding, prefix validation, and null-byte suffix bypasses.

## The map

| Broken assumption | Payload shape |
|-------------------|---------------|
| user filename stays under image directory | `../../../etc/passwd` |
| blocking `../` is enough | `/etc/passwd` |
| one strip pass removes traversal | `....//....//....//etc/passwd` |
| validation before final decode is safe | `..%252f..%252f..%252fetc/passwd` |
| raw prefix means containment | `/var/www/images/../../../etc/passwd` |
| suffix check survives truncation | `../../../etc/passwd%00.png` |

## Start with the filesystem, not the string

The simple case is direct:

```http
GET /image?filename=../../../etc/passwd
```

The application joins the filename to an image directory, then the filesystem resolves the traversal segments.

If traversal sequences are blocked, an absolute path may still work:

```http
GET /image?filename=/etc/passwd
```

This shows why a blacklist of `../` is incomplete. The path can escape without containing a traversal sequence at all.

## Filters are not canonicalization

Non-recursive stripping is a classic trap:

```text
....//....//....//etc/passwd
```

Remove `../` once and the remaining characters collapse back into traversal. Filtering strings is not the same thing as resolving paths.

Double decoding is the same problem in a different layer:

```text
..%252f..%252f..%252fetc/passwd
```

One decode turns `%25` into `%`, leaving `%2f`. A later decode turns it into `/`. If validation happens between those steps, it validates the wrong representation.

## Prefix and suffix checks are not containment

This string starts with the expected directory:

```text
/var/www/images/../../../etc/passwd
```

The canonical path does not stay there. Directory containment must be checked after resolving the path.

The null-byte lab demonstrates the suffix version:

```text
../../../etc/passwd%00.png
```

The validation layer sees `.png`. A lower-level file API or compatibility layer may truncate at the null byte and open `/etc/passwd`.

## Defender notes

Hardening:

- prefer opaque file IDs mapped to server-side allowlists;
- decode and normalize exactly once before validation;
- resolve the canonical path with `realpath` or an equivalent API;
- check that the canonical path is inside the intended base directory;
- reject absolute paths, drive letters, UNC paths, mixed separators, encoded separators, and null bytes;
- treat extension checks as file-type checks, not directory containment;
- keep the web process unable to read sensitive OS paths.

Detection:

- `filename`, `path`, `file`, `image`, or `avatar` parameters containing `../`, `..\\`, `%2e`, `%2f`, `%5c`, or `%00`;
- nested traversal strings such as `....//`;
- double-encoded separators such as `%252f`;
- valid directory prefixes followed by traversal segments;
- image endpoints returning `/etc/passwd`-like content;
- file errors that disclose local base directories.

The rule is simple: validate the canonical path, not the user-supplied string.
