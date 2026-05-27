---
layout: post
title: "Testing the Four-Axis Detection Rubric Against CVE-2024-4956"
date: 2026-05-30 10:00:00 +0800
categories: [detection-engineering, methodology]
tags: [cve-2024-4956, nexus, signal-quality, rubric, jetty, path-traversal]
related_posts:
  - three-2024-cves-detection-signal-quality
  - geoserver-cve-2024-36401-anatomy
  - picking-cves-detection-triage
---

At the end of [last week's post](https://1392081456.github.io/2026/05/29/three-2024-cves-detection-signal-quality/) I made a small public commitment. The post had introduced a four-axis rubric for predicting detection-rule effort (**specificity / position / encoding / workflow uniqueness**), and the closing paragraph picked the next CVE on my queue and scored it in advance: *CVE-2024-4956 (Nexus Repository Jetty path traversal), preliminary scoring H/H/M/V-H, estimated rule shape single selection with URL-encoded variant.* The post promised to come back at the end of the week with the actual result.

This is the come-back post. The rubric was right on three axes and **partly wrong on one**, which turned out to be more interesting than getting all four right.

## The bug, briefly

CVE-2024-4956 affects Sonatype Nexus Repository Manager 3 versions before 3.68.1. Nexus is fronted by an embedded Jetty server, and a behaviour quirk in Jetty's `URIUtil.canonicalPath()` resolves a leading empty path segment — produced by URL-encoded slashes such as `%2F%2F` — to the filesystem root rather than the web context root. Combined with `..%2F` traversal, the bug allows an unauthenticated attacker to read any file the `nexus` user can read with a single `GET`:

```
GET /%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
Host: nexus.target:8081
```

There is no authentication, no special header, and no exploit chain. One request out, one file in. The CVSS is "only" 7.5 because the impact is file read rather than RCE, but in practice the file read includes `admin.password` and `nexus.properties` on default installs, so the bug is closer to "credential disclosure" than to "low-impact info-leak."

## The pre-write prediction

The four-axis scoring I committed to in last week's post was:

| Axis | Pre-score | Reasoning |
|---|---|---|
| **Specificity** | High | The byte pair `%2F%2F` followed later in the same URI by `..%2F` is essentially attacker-only. No legitimate client emits doubled URL-encoded slashes. |
| **Position** | High | The pattern lives in `cs-uri-stem` at structurally constrained positions. |
| **Encoding** | Medium | URL-encoding case variants (`%2f` vs `%2F`) are trivial bypasses; the rule needs case-insensitive matching, which Sigma's `|contains` is not. |
| **Workflow** | Very High | No legitimate Nexus user navigates with doubled-encoded slashes; even crawlers, package managers, and Maven clients do not produce this shape. |

Predicted rule shape: a single `selection` on the URI pattern, with an explicit enumeration of case variants to handle the encoding axis. Estimated authoring time: **2-3 hours including reproduction**.

## What actually happened

I stood up vulhub, hit the bug, and started writing. The scorecard, post-hoc:

| Axis | Pre-score | Post-score | Drift |
|---|---|---|---|
| Specificity | High | High | ✓ as predicted |
| Position | High | High | ✓ as predicted |
| Encoding | Medium | **Low** | ↓ a notch |
| Workflow | Very High | Very High | ✓ as predicted |

Three axes correct, one drifted one step downward. The reason the encoding axis turned out worse than I expected is what I want to dwell on, because it changed the rule shape.

### Why Encoding dropped from Medium to Low

I had anticipated two URL-encoding variants — `%2F%2F` and `%2f%2f`. What I had not anticipated was that Jetty's path canonicalisation accepts a *mixture* of additional benign-looking encodings inside the same URI:

```
/%2F%2F..%2F..%2F..%2Fetc%2Fpasswd          # canonical attack
/%2f%2F..%2f..%2F..%2Fetc%2Fpasswd          # mixed case
/%2F%2F.%2e%2F.%2e%2F.%2e%2Fetc%2Fpasswd    # double-encoded dot segments
/;%2F%2F..%2F..%2F..%2Fetc%2Fpasswd         # leading path parameter
/repository/maven-public%2F%2F..%2F..%2Fetc%2Fpasswd   # benign prefix
```

The last form is the one that surprised me. Nexus uses path prefixes like `/repository/maven-public/` as the entry to its package indexes — and **the bug fires through that path too**, because the `%2F%2F` segment resets the canonicalisation regardless of what precedes it. A rule that requires `/repository/` does not just *accept* this benign-prefix variant; it *requires* the benign prefix in order to avoid alerting on every Nexus health-check that happens to URL-encode something.

What I had pre-scored as "trivially bypassable but case-only" is actually "many semantically distinct payload shapes." The encoding-axis weakness is structural, not cosmetic.

### The rule I ended up shipping

Instead of the single-selection rule I expected to write, the version under `rules/nexus_2024_4956/` in [sigma-detection-rules](https://github.com/1392081456/sigma-detection-rules/tree/main/rules/nexus_2024_4956) is two-stage:

```yaml
detection:
    selection_doubled_slash:
        cs-uri-stem|contains:
            - '%2F%2F'
            - '%2f%2f'
            - '%2F%2f'
            - '%2f%2F'
    selection_traversal:
        cs-uri-stem|contains:
            - '..%2F'
            - '..%2f'
            - '%2E%2E%2F'
            - '%2e%2e%2F'
            - '%2E%2E%2f'
            - '%2e%2e%2f'
    filter_legitimate_repo_root:
        cs-uri-stem|endswith: '/'
        cs-uri-stem|contains: '/repository/'
        cs-uri-stem|contains|not:
            - '%2F'
            - '%2f'
    condition: selection_doubled_slash and selection_traversal and not filter_legitimate_repo_root
```

Two `selection_*` for the attack shape, one `filter_*` to remove the (rare but real) case where someone hits a repository root URL that legitimately ends in `/` after legitimate encoded slashes elsewhere. **Three components**, against my predicted one. The authoring time was 4.5 hours, not 2-3 — most of the extra time spent enumerating encoding variants in the test corpus.

## What the drift tells me about the rubric

The point of the rubric, recall, is to *predict* rule effort *before* writing. The Nexus result tells me three useful things:

> 1. **The rubric is directionally right but the Encoding axis has more granularity than four buckets allow.** "Medium" is concealing a real distinction between "case-only bypass" and "many semantic variants." I will probably split Encoding into two sub-axes for the next pass: *Lexical encoding* (case, percent variants) and *Semantic encoding* (genuinely different payload shapes that exploit the same code path).
> 2. **The rubric correctly forecast which axes would dominate the authoring cost.** Specificity / Position / Workflow being High meant the rule had a clean shape to aim at; the time blew up only on the axis I had pre-flagged as weak.
> 3. **Pre-scoring is genuinely cheap.** The fifteen minutes I spent assigning four letters before reproducing the bug paid for itself by making the surprise *recognisable as a surprise* rather than a vague "this is taking longer than expected" feeling.

I will keep doing this — score before writing, post-score after writing, look at the drift, refine the rubric — as a standing practice for the next set of CVEs. The detail of how I refine it (Encoding split into two, possibly an additional "Cardinality of vulnerable endpoints" axis I am considering after this case) is something I will only post once I have at least three more CVEs through the procedure. Two-data-point methodology is not yet methodology.

## A note on humility

There is a slightly uncomfortable thing about publishing a rubric one week and showing its first prediction was partly wrong the next. The instinct of a vendor blog would be to either skip the post entirely or to retroactively redefine the prediction so it looks accurate. I am writing this up the other way — the prediction is on record, the result is on record, the delta is the post — because the rubric becomes useful only when it has been falsified at least once and survived. A rubric that was right four-out-of-four on its first try would be either a coincidence or a sign that the axes were too coarse-grained to catch reality. Catching reality is the goal.

The next CVE I will pre-score is [CVE-2024-9264](https://nvd.nist.gov/vuln/detail/CVE-2024-9264), the Grafana DuckDB extension SQL injection that turns into shell access through `shellfs`. Preliminary score, written before reproduction: **High / Medium / Medium / High**. I will know in a week.

## References

- Upstream Nexus advisory: [GHSA-h2hf-w28w-h6c4](https://github.com/sonatype/nexus-public/security/advisories) (vendor)
- vulhub reproduction: [`vulhub/nexus/CVE-2024-4956`](https://github.com/vulhub/vulhub/tree/master/nexus/CVE-2024-4956)
- Local Sigma rule and writeup: [`labs/nexus_2024_4956`](https://github.com/1392081456/ctf-notes/tree/main/labs/nexus_2024_4956) in `ctf-notes`
