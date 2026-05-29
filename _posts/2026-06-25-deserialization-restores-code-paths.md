---
layout: post
title: "Deserialization Restores Code Paths"
date: 2026-06-25 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [deserialization, gadget-chain, phar, portswigger]
related_posts:
  - ssti-is-context-first
  - authorization-is-not-a-route-name
  - path-traversal-is-a-canonicalization-bug
---

Unsafe deserialization is usually described as "turning bytes back into objects". That is too gentle. In a real application, deserialization restores code paths: constructors, magic methods, getters, cleanup hooks, template rendering, and file operations.

The ten PortSwigger labs are a useful ladder from simple field tampering to PHAR-triggered gadget chains.

## Start with the format

Format recognition is the first speed win:

- PHP serialization: `O:`, `s:`, `b:`, `i:`;
- Java serialization: `AC ED 00 05`, often Base64 as `rO0AB`;
- Ruby Marshal: Rails/Ruby session blobs;
- PHAR: PHP archive metadata reached through `phar://`.

Then ask whether integrity is enforced. Base64 is not integrity. A signed cookie is only as strong as the secret and the surrounding debug hygiene.

## Field changes are already impact

The early labs need no gadget chain.

```php
s:5:"admin";b:0;
```

becomes:

```php
s:5:"admin";b:1;
```

That is enough if the application trusts the restored object.

The type-confusion variant uses PHP 7-era loose comparison:

```php
s:8:"username";s:13:"administrator";
s:12:"access_token";i:0;
```

The habit to build here is exactness. Serialized string lengths are part of the syntax, and a one-byte mismatch prevents the object from loading.

## Application features become gadgets

A gadget does not have to execute a shell. In one lab, the account-deletion feature deletes the current user's avatar path. If that path is restored from a client-controlled object, changing it to another file turns a normal feature into the primitive.

That same idea scales. PHP source backups reveal classes with cleanup behavior. A `CustomTemplate` object with a controlled `template_file_path` becomes a file-deletion gadget.

## Pre-built chains are classpath questions

Java with Apache Commons Collections is a classpath problem. If a known gadget library is present, ysoserial can generate the object:

```bash
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w0
```

Symfony is a signing problem layered on top. A debug page leaks `SECRET_KEY`, PHPGGC generates the object, and HMAC-SHA1 makes the cookie valid again.

Ruby follows the same pattern with a documented RubyGems Marshal chain.

## Custom chains are source-reading exercises

When pre-built gadgets stop working, source code becomes the map. Start from the method that will run automatically: `readObject`, `__destruct`, `__wakeup`, `__toString`, `__call`. Follow controllable fields until they reach a sink: a file path, command, template, SQL query, or URL fetch.

The best way to reason about a POP chain is as a dataflow graph:

```text
attacker field -> automatic method -> intermediate object -> sink
```

Every edge must be triggered by the application without needing a method call you cannot make.

## PHAR hides the deserialize call

The PHAR lab is the one to remember. There is no obvious `unserialize()`. A file function sees `phar://`, reads archive metadata, and triggers PHP object restoration.

The final chain combines:

- JPG upload acceptance;
- PHAR metadata;
- source-discovered PHP objects;
- Twig SSTI in a property;
- `file_exists()` as the trigger.

That is why deserialization review should include file wrappers and upload paths, not just explicit deserializer calls.

## Defender notes

Hardening:

- avoid native deserialization on untrusted input;
- use server-side sessions or strict JSON schemas;
- treat signing keys as secrets and remove debug leakage;
- use class allowlists where deserialization is unavoidable;
- keep paths, commands, templates, and delete targets out of client-restored objects;
- restrict PHAR wrappers and file operations over uploaded content.

Detection:

- serialized magic strings in cookies and request bodies;
- sudden session-cookie growth;
- `.php~`, `phpinfo.php`, directory-index, and `phar://` probes;
- deserialization stack traces and gadget-library class names;
- account or avatar actions touching another user's home directory.

The durable rule is that an object graph is executable application structure. If the user controls the graph, they may control the path through the program.
