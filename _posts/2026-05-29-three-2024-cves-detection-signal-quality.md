---
layout: post
title: "Three 2024 N-days, Three Signal Qualities — Why Jenkins is Easier to Detect Than GeoServer"
date: 2026-05-29 10:00:00 +0800
categories: [detection-engineering, methodology]
tags: [cve-triage, signal-quality, jenkins, teamcity, geoserver, sigma]
related_posts:
  - geoserver-cve-2024-36401-anatomy
  - cve-to-sigma-30min
  - picking-cves-detection-triage
---

There is a counter-intuitive thing I learned writing detection rules for the 2024 CVE harvest. The CVEs that were *worst* for victims were not always the worst to detect. CVSS does not predict detection effort. Bug class does not predict it either. The one variable that does predict it — and I have never seen the variable named in any of the standard CVE triage frameworks — is what I will call **detection signal quality**: the byte-level distance between the attacker's request and the closest legitimate request the application accepts.

This post walks through three CVEs I reproduced in 2024 — Jenkins CLI ([CVE-2024-23897](https://nvd.nist.gov/vuln/detail/CVE-2024-23897)), TeamCity ([CVE-2024-27198](https://nvd.nist.gov/vuln/detail/CVE-2024-27198)), and GeoServer ([CVE-2024-36401](https://nvd.nist.gov/vuln/detail/CVE-2024-36401)) — and shows why writing detection content for them took **2 hours, 3 hours, and 8 hours respectively**, even though all three are unauthenticated RCEs or equivalent in impact.

## What "signal quality" actually means

When I write a Sigma rule, I am effectively answering one question: *given a request my rule fires on, what is the probability that the request came from an attacker and not from a legitimate user of the application?* Call that probability `P(attack | match)`. A high-quality detection signal is one where `P(attack | match)` is close to 1 with a simple rule. A low-quality signal is one where `P(attack | match)` is, with the obvious rule, somewhere around 0.5 — half the alerts will be benign — and the work of detection engineering is to climb that number back up to something useful.

Four factors push signal quality up or down. I will reuse them throughout this post:

> 1. **Specificity** — Is the attacker's byte sequence one that legitimate clients of this service essentially never produce?
> 2. **Position** — Does it appear at a location in the request (path, header, query parameter, body field) that is structurally constrained, or somewhere a freeform string could land?
> 3. **Encoding robustness** — Can the byte sequence survive simple URL-encoding, base64 wrapping, or normalisation, or does the attacker have many trivial bypasses?
> 4. **Workflow uniqueness** — Is there a real workflow inside the application where a legitimate user would produce the same byte sequence?

A CVE with strong scores on all four is a rule you can ship in an afternoon and forget about. A CVE with one weak score is a rule you will tune for a week. A CVE with two or more weak scores might not be worth writing a *blocking* rule at all — it belongs as a hunting query.

Here is how the three 2024 CVEs score.

## CVE-2024-23897 — Jenkins CLI `@filename`

**Score: 9/10. The platonic ideal.**

The flaw: the Jenkins CLI parser interprets any argument that starts with `@` as a path to a file whose contents should be read into the argument. The CLI itself is a Java client, but the same parser runs server-side via `/cli` — so an unauthenticated HTTP request can ask the server to read arbitrary files. The PoC is one line:

```
POST /cli?remoting=false HTTP/1.1
Host: jenkins.target
Content-Type: application/octet-stream

[binary frame: Command="who-am-i", arg="@/etc/passwd"]
```

Now score it.

> **Specificity** — High. The character `@` at the start of a CLI argument is a Jenkins-specific convention. It does not appear in any legitimate Jenkins HTTP request that I can construct.
>
> **Position** — High. The `@/...` token shows up at a specific offset of the binary CLI frame, which itself only ever shows up against `/cli`. Two structural constraints stacked.
>
> **Encoding robustness** — High. The `@` byte cannot be substituted; the Jenkins server-side parser only recognises that exact byte. URL encoding the `@` produces a request that does not trigger the bug.
>
> **Workflow uniqueness** — Very high. No legitimate browser-driven Jenkins workflow goes anywhere near `/cli` with `@`-prefixed CLI args. Real admins use the standalone CLI binary against the Jenkins SSH port, which doesn't touch this code path at all.

A single-selection Sigma rule that fires on `cs-uri-stem endswith /cli` and `cs-request-body contains @/` is enough. False positives in my lab: zero across 48 hours of background Jenkins traffic. The detection rule is shorter than the reproduction notes.

## CVE-2024-27198 — TeamCity path-parameter auth bypass

**Score: 9/10. Even cleaner, in a different way.**

The flaw: the TeamCity request router strips RFC 3986 path parameters before deciding whether a path requires authentication, but the underlying handler sees the un-stripped path. So a request to `/.;/admin/users` is auth-checked as `/.;/admin/users` (no auth required for this synthetic path), but routed to `/admin/users` (which would normally require auth). The PoC is one `curl`:

```
GET /.;/app/rest/users/id:1/tokens/RPC HTTP/1.1
Host: teamcity.target
```

Score:

> **Specificity** — Extremely high. The byte sequence `/.;/` is RFC 3986 path-parameter syntax that no real client emits as part of normal navigation. Even pen-test tooling rarely produces it by accident.
>
> **Position** — High. It appears in `cs-uri-stem` at a structurally defined position (the path), not in a freeform field.
>
> **Encoding robustness** — Medium. The attacker can URL-encode the `.` and `;` (`%2E%3B%2F`). Sigma's `|contains` is byte-level, so a single-form rule will miss the encoded variant. The mitigation is to add the encoded forms as additional selections — three extra lines of YAML — but the work has to be done explicitly. This is the only ding against the rule.
>
> **Workflow uniqueness** — Very high. No real TeamCity user navigates with `.;` in the path. Even crawlers and CI/CD probes do not produce it.

Two stacked selections (raw + URL-encoded variants) and the rule is done. False positives in a busy CI environment: zero in 72 hours. The work was mostly *enumerating* the encoding variants, not designing detection logic.

## CVE-2024-36401 — GeoServer OGC Filter JXPath evaluation

**Score: 6/10. The hard one.**

The flaw: GeoServer evaluates OGC API property identifiers (`propertyName`, `valueReference`, `sortBy`) through the JXPath engine, which resolves `java.lang.Runtime.getRuntime().exec(...)` as if it were a property path. The detection signal looks deceptively similar to the other two — just `Runtime.getRuntime` in a query parameter, right? — but the four factors score very differently.

> **Specificity** — Medium. The substring `Runtime` is a legal feature name in some GeoServer datasets. The substring `getRuntime()` is essentially attacker-only, but `Runtime` alone is not.
>
> **Position** — Medium. The OGC parameters appear in URI query *or* in POST body (OGC supports both transport forms), and the legal CQL filter grammar permits a lot of function call syntax that overlaps with the payload syntax.
>
> **Encoding robustness** — Low. The payload survives URL-encoding (legal in OGC), and the attacker can additionally rewrite `java.lang.Runtime` through reflection variants (`Class.forName("java.lang.Runtime")...`) that do not contain the substring. A serious attacker has many bypasses.
>
> **Workflow uniqueness** — Medium. Legitimate WFS clients submitting complex XPath expressions in `propertyName` are rare but not unheard of. A "WFS client referencing Java class names" is not a category I can rule out by hand-waving.

This is where I spent the bulk of my eight hours on the CVE. The shape of the rule I eventually shipped — and which is now under review as [SigmaHQ/sigma#6032](https://github.com/SigmaHQ/sigma/pull/6032) — is a three-stage `AND`:

```yaml
condition: all of selection_*
# selection_endpoint:    /geoserver/
# selection_ogc_param:   propertyName= | valueReference= | sortBy=
# selection_payload:     Runtime.getRuntime | ProcessBuilder | ...
```

The full anatomy of why is in [yesterday's post](https://1392081456.github.io/2026/05/28/geoserver-cve-2024-36401-anatomy/). The takeaway for this post is that **the three-stage `AND` is the structural cost of a medium-quality signal**. If GeoServer had scored 9/10, a single selection would have been enough. Scoring 6/10 forces a multi-stage rule, an `experimental` status, a wider `references` list, and several pages of false-positive analysis in the PR.

## The pattern across the three

Here is the same data in one table:

| CVE | Service | Spec. | Pos. | Enc. | Wkflw. | Rule shape | Hours |
|---|---|---|---|---|---|---|---|
| 23897 | Jenkins | High | High | High | V-High | Single selection | 2 |
| 27198 | TeamCity | V-High | High | Medium | V-High | Raw + encoded variants | 3 |
| 36401 | GeoServer | Medium | Medium | Low | Medium | Three-stage `AND` | 8 |

The relationship is monotonic. Each axis that drops from "high" to "medium" adds a small extra requirement to the rule. Each axis that drops to "low" — like GeoServer's encoding robustness — adds a substantial one. The total engineering cost is roughly the *product* of the missing axes, not the sum, because each weakness compounds the others.

This is also why CVSS does not predict detection effort. All three CVEs are CVSS 9.8 unauthenticated RCEs. CVSS describes what the bug *does to the victim*, not what its byte-level signal looks like on the wire.

## When to write a hunting query instead

If a CVE scores **two or more "low" axes**, I no longer write a real-time alerting rule for it. I write a hunting query instead — a query the analyst runs on demand against a longer time window, with the expectation of triaging the results manually. The rationale: a low-quality signal turned into a real-time alert produces enough false positives that the analyst will silence the rule within a week, at which point you have *negative* detection (the rule is in the SIEM, nobody trusts it, real hits are dismissed because the rule "always cries wolf"). A hunting query produces fewer alerts and the analyst's expectation is calibrated to triage them.

I have not yet written up the hunting-query side of the picture in detail. The current `hunting/` directory in [`sigma-detection-rules`](https://github.com/1392081456/sigma-detection-rules/tree/main/hunting) has six CVEs in three SIEM dialects, but I picked those six on bug class rather than signal quality. Re-picking them by the four-axis rubric in this post would probably swap two of the entries; I will redo that exercise in a future post.

## The rubric, packaged

For anyone running a 2026 CVE queue, here is the rubric I now apply *before* picking a CVE to write detection content for:

> 1. Score the candidate CVE on **specificity / position / encoding / workflow uniqueness** — High / Medium / Low for each.
> 2. If three or four are High: write the rule. Single selection or two-stage. Ships in an afternoon.
> 3. If one or two drop to Medium: write the rule with a multi-stage `AND` and `experimental` status. Ships in a day.
> 4. If two or more drop to Low: write a hunting query, not a blocking rule.
>
> CVSS is irrelevant to which row applies.

The next CVE in my queue is [CVE-2024-4956](https://nvd.nist.gov/vuln/detail/CVE-2024-4956), the Nexus Repository Jetty path-traversal. My initial scoring: H / H / Medium / V-High. Estimated rule shape: single selection with URL-encoded variant. I will know by the end of the week whether the four-axis rubric was right about it.
