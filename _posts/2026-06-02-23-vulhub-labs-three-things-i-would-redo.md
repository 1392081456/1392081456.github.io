---
layout: post
title: "23 vulhub CVE Labs Later — Three Things I Would Redo From the Start"
date: 2026-06-02 10:00:00 +0800
categories: [detection-engineering, methodology, retrospective]
tags: [vulhub, retrospective, lessons-learned, sigma, lab-design]
related_posts:
  - testing-four-axis-rubric-against-nexus-4956
  - picking-cves-detection-triage
  - cve-to-sigma-30min
---

The [labs chapter](https://github.com/1392081456/ctf-notes/tree/main/labs) currently contains **23 published CVEs**, each reproduced in an isolated vulhub container and ending in a full SOC artefact set (Sigma rule, Suricata signature, IOC table, three-SIEM hunt queries). The oldest in the chapter is Shiro CVE-2016-4437, written in late 2024. The newest at time of writing is the ActiveMQ Jolokia chain (CVE-2026-34197). That spans roughly a year of evening-and-weekend work and ten calendar years of CVE coverage.

Most retrospectives I have read at this milestone are celebratory ("here is what I did and why it was great"). I want to write the other kind. Three things I would redo from scratch if I were starting the labs chapter today — concrete, specific, with the choice I made the first time and the choice I would make now.

## 1. PCAP, not `curl`, as the source of truth

**What I did the first time.** Every writeup includes a reproduction section structured around `curl` commands. For Shiro:

```bash
curl -X POST http://target:8080/login -H 'Cookie: rememberMe=<base64 payload>'
```

For Jenkins CLI:

```bash
curl -X POST 'http://target:8080/cli?remoting=false' \
  --data-binary @command.bin
```

These work. They are also the wrong primary artefact, because the `curl` command is an *abstraction* of the request — it does not record how Jenkins's binary frame is actually serialised on the wire, what HTTP/2 framing applies, what the order of headers is, or what the exact byte sequence of the cookie value looks like after the user-agent's encoder gets done with it.

**Why this mattered.** I wrote two early Sigma rules from the `curl` commands directly, without inspecting the actual packet trace. Both rules silently missed real-world variants:

- The Shiro rule looked for the literal cookie name `rememberMe=` but missed the case where Tomcat had already URL-encoded the leading `=` of base64 padding.
- The Jenkins rule looked for the string `cli?remoting=false` but missed the trailing-slash variant `/cli/?remoting=false`, which the Jenkins binary client also accepts.

Neither failure was catastrophic, but both were embarrassing — the rule that exists to detect a specific exploit *should* match the specific exploit, and matching the abstraction-layer-up *instead of* the wire format is the silent failure mode of detection content.

**What I would do now.** Every lab would ship with a redacted `.pcap` capture of the reproduction request alongside the `curl` command, and the writeup would derive the rule from the packet capture, not the curl invocation. I would not commit large binary pcaps to git — instead I would commit the `tcpdump -A -q` ASCII excerpt as a `wire.txt` file, with the same artefact discipline as the Sigma rule. The git diff would let me track wire-format changes the same way I track rule changes.

The retrofit cost for the existing 23 labs is roughly one hour per lab to capture and excerpt. I am doing it as a background task. The newer labs from CVE-2024-* onwards are already done; the 2016-2023 long tail is the gap.

## 2. Pre-score CVEs with the four-axis rubric *before* adding them to the queue

**What I did the first time.** The first ~15 CVEs in the chapter were picked by gut. The criteria were "this looks interesting" + "vulhub has the docker-compose for it" + "I can read enough of the code to understand the boundary." That gave a perfectly fine but somewhat arbitrary mix of bug classes: a lot of Java deserialization (because I was getting good at it), one Redis abuse case, one ZeroShell command injection, and the inevitable Log4Shell.

**Why this mattered.** Two of those 15 labs turned out to be detection-engineering dead ends in retrospect, and one was a partial win:

> 1. **ComfyUI CVE-2026-22777** — a CRLF injection that downgrades the config and then RCE. Detection of the CRLF is technically possible but the workflow uniqueness was Low (legitimate ComfyUI extensions also write to config), so the rule landed `experimental` and was never high-confidence. Worth writing? Marginal.
> 2. **OpenClaw CVE-2026-25253** — Cross-Site WebSocket Hijacking in a small open-source game project. Bug is real. But OpenClaw has approximately zero enterprise deployment, so the detection rule will never run against meaningful traffic. Pure exercise value.
> 3. **Chartbrew CVE-2026-25887** — MongoDB `new Function()` RCE. The bug is generalisable (the pattern recurs across MongoDB integrations), but the rule has high specificity only on the *exact* exploit shape; variants will dodge it.

If I had pre-scored those three on the four-axis rubric ([from the post two weeks ago](https://1392081456.github.io/2026/05/29/three-2024-cves-detection-signal-quality/)), the labour budget for at least the OpenClaw one would have gone elsewhere.

**What I would do now.** Every CVE goes through a pre-score gate before joining the queue. The gate is mechanical: assign H/M/L/V-H to each of the four axes, decide the rule shape that score implies (single selection / multi-stage AND / hunting query), and only then commit the lab to the queue. The score is recorded in the writeup's frontmatter so I can audit it after the fact, the way [the Nexus 4956 post](https://1392081456.github.io/2026/05/30/testing-four-axis-rubric-against-nexus-4956/) audits its own prediction.

This is not a perfectionist optimisation. It is a labour budget. A CVE that *should* be a hunting query but gets written up as a real-time rule consumes 4-6 hours of effort to produce something the SIEM will never trust. The pre-score gate avoids that.

## 3. A `deprecated` status workflow for rules whose substrate changed

**What I did the first time.** Every rule in [`sigma-detection-rules`](https://github.com/1392081456/sigma-detection-rules) is `status: stable` or `status: experimental`. Nothing in the repository is marked `deprecated`, which the SigmaHQ schema explicitly allows.

**Why this mattered.** Shiro CVE-2016-4437's detection rule keys on the hard-coded default AES key `kPH+bIxk5D2deZiIxcaaaA==` because real-world exploits use it. Apache Shiro patched the default key generation in 2016 and changed the cookie envelope format twice since. The rule still fires on the *historical* signal — anyone using a still-vulnerable Shiro that still has the original key — but the base rate of new attacks against that exact signal is now low enough that the rule mostly serves as a tripwire for legacy systems, not a primary detection. That is a different role from "this rule catches current threats," and the SIEM team should know which role they are deploying.

The same pattern is becoming visible for the Log4Shell rule. The original `${jndi:ldap://` substring catches script-kiddie scans but no longer catches anything resembling current-day Log4Shell exploitation, which goes through more sophisticated evasion (control-character padding, exec context lookups, recursive expansion). My rule still fires; the *useful new signal* lives elsewhere.

**What I would do now.** Two changes. First, every rule gets a periodic review (every 6 months) where I decide whether its base rate of true-positive detection is still meaningful, and if not, I move it to `status: deprecated` with a clear pointer to the rule that has succeeded it. The deprecated rules stay in the repository — they are useful as detection content for *the historical signal* — but the SIEM team has the metadata to triage their deployment differently. Second, the `sigma-detection-rules` CI would warn on any commit that adds a new rule to a CVE directory where an existing rule has been `deprecated` longer than a year without being replaced, since that is usually a sign that the CVE itself has aged out of relevance and the lab should be archived rather than re-detected.

Both of those changes are workflow, not technique. I am writing the GitHub Action for the periodic review now; expect it in the repository inside the next two weeks.

## What stays unchanged

The four-step pipeline — Reproduce → Sigma rule → Suricata signature → SIEM hunt queries — is the one thing from a year ago that I would not touch. It survived every CVE class in the chapter, including the ones that broke other things about my workflow. [The first post in this series](https://1392081456.github.io/2026/05/26/cve-to-sigma-30min/) described it in detail and the description still holds.

The other thing that stays unchanged is the discipline around scope: every lab uses a locally-hosted, vendor-patched vulhub container or an equivalent isolated lab VM, with no production system or third-party service touched at any stage. The scope statement at the top of every artefact repository is not boilerplate; it is the constraint that lets this work be defensive research instead of something else. I would not relax it.

## What I plan to write up next

Three retrospective topics are on the bench, in rough order of how much I have ready:

- A specific look at the **Fastjson 1.2.24** lab, which is the one CVE where the four-step pipeline genuinely struggled (the cookie-deserialization shape is not visible on a webserver log line — it needs application-level instrumentation). What I did instead and what the result looked like.
- A side-by-side of the **three SIEM dialects** in the hunting/ directory (Splunk SPL, Sentinel KQL, Elastic ES|QL) on the same CVE, with the observation that the SIEM choice constrains the *kind* of hunt question you can ask, not just the syntax.
- The retirement workflow for old detection content described in section 3 above — once the GitHub Action ships.

I will get to them in that order.
