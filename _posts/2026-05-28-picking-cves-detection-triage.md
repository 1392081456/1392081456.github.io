---
layout: post
title: "How I Pick CVEs to Reproduce — Detection Engineering as Triage"
date: 2026-05-28 10:00:00 +0800
categories: [detection-engineering, methodology]
tags: [vulhub, cve-triage, prioritization, soc-economics]
related_posts:
  - three-2024-cves-detection-signal-quality
  - geoserver-cve-2024-36401-anatomy
  - cve-to-sigma-30min
  - pwn-to-falco-rules
---

[vulhub](https://github.com/vulhub/vulhub) is the canonical catalogue of "vendor-patched CVEs that ship with a `docker-compose.yml`" — at the time of writing it covers somewhere north of 200 vulnerabilities across roughly 100 products. I have written full reproduction-plus-detection writeups for **23** of them, packaged as the [labs chapter](https://github.com/1392081456/ctf-notes/tree/main/labs). The other ~180 I have not touched.

The most useful question I have ever been asked about my labs chapter is: *"How did you pick which 23?"* This post is the answer, framed as a triage rubric that the reader can apply to their own queue.

## Why this matters

Most defenders cannot afford to write detection content for every published CVE. The labour cost is real: my own per-CVE writeup (reproduce → understand → Sigma + Suricata + multi-SIEM hunt + IOC table) averages **4 to 6 hours**. With 200 CVEs to choose from, that's a thousand engineer-hours to clear the queue. Nobody has those hours. So the question is which CVEs are worth those hours — and the answer is not "the ones with the highest CVSS."

The default heuristic in industry is something like *"reproduce the loud ones"* (Log4Shell, Spring4Shell, Heartbleed). But that's barely a rubric. The 23 CVEs in my labs chapter were picked by a four-question filter that I refined over the course of the work. Here it is.

## The four-question filter

For every candidate CVE in the queue, I ask:

> **Question 1 — Is the parsing boundary cleanly observable?**

If yes → continue. If no → skip.

This is the question I introduced in [the first methodology post](https://1392081456.github.io/2026/05/26/cve-to-sigma-30min/). A vulnerability is worth reproducing if the dangerous user-controlled bytes cross a *named, observable boundary* — an HTTP header, a cookie, a URI parameter, a JSON field, a wire protocol frame. If the attack happens inside a binary opaquely (e.g., a use-after-free that only the attacker's heap shaping triggers, with no externally observable precondition), the detection rule will be either trivial ("alert on the post-exploit child process") or impossible. Neither is useful.

Of vulhub's catalogue, this filter alone removes about **30%** — mostly memory-corruption CVEs in C/C++ services and Linux kernel issues where the dangerous data path is internal.

> **Question 2 — Does the bug class generalize beyond this one CVE?**

If yes → strong candidate. If no → low priority unless the CVE is *especially* high impact.

Example of a generalizing class: Java cookie deserialization (Shiro CVE-2016-4437). Writing a detection rule for it teaches me how to detect the *next* Java deserialization CVE — and there will be one, every year, forever. The pattern recurs: ViewState, JSF, Spring sessions, JBoss sessions, custom Shiro forks.

Example of a non-generalizing CVE: A path-traversal bug in one specific filesystem-walk function of one specific firmware version of one specific IoT device. Writing the rule teaches you only about that device. The same labour spent on a more generalizable bug pays off across the next 5 years of new CVEs in adjacent classes.

This filter is *the* reason my labs chapter is dominated by `web` and `serialization` CVEs and lighter on `IoT firmware` and `mobile` ones. Both are real bug categories, but the per-rule reusability of the rules-against-web-serialization cluster is dramatically higher.

> **Question 3 — Does the SOC of a realistic target see this in their logs?**

If yes → strong candidate. If no → demote.

This sounds obvious but it is the question least asked. A defender writing a Sigma rule against "ActiveMQ OpenWire deserialization (CVE-2023-46604)" needs to first ask: *does the target SOC actually monitor port 61616?* Many do not. A rule for an unmonitored protocol catches zero attacks, no matter how technically correct it is.

I weight this question heavily for any non-HTTP protocol bug (OpenWire, RMI, RDP, SMB-Direct, AMQP). The rule is still worth writing because some SOC somewhere does monitor that protocol — but the **hunting query** (for retroactive log analysis) tends to be more useful than the **alert rule** (for real-time fire) when the protocol is rarely logged.

This is why my [hunting/](https://github.com/1392081456/sigma-detection-rules/tree/main/hunting) directory exists at all. The Sigma alert rule catches the next attack, but the hunting query catches the previous one — which is sometimes the only thing the SOC can actually do.

> **Question 4 — Will I learn something I didn't already know?**

If yes → personally motivated, do it. If no → leave it for someone else.

This is the most subjective filter and I keep it last. After question 1-3 have done their work, the remaining candidate list is often 30-40 CVEs. The final 23 was simply: which of these will teach me a new technique, a new bug class, or a new detection trick.

A few examples of CVEs I picked specifically because of question 4:

- **CVE-2026-22777 (ComfyUI-Manager CRLF → config downgrade → RCE)** — teaches CRLF injection into a YAML/JSON config writer, which then disables a downstream security control. The chain is multi-step and novel.
- **CVE-2026-25887 (Chartbrew MongoDB `new Function()`)** — teaches Node.js sandbox escape via `global.process.mainModule.require('child_process')`. Not in my prior playbook.
- **CVE-2025-49001 (DataEase JWT verification exception caught but not aborted)** — teaches a bug pattern (`try { verify(token) } catch { /* swallow */ }`) that I've now seen four times in different products.

I would not have picked these on impact alone — they were question-4 picks. They turned out to be among the most generally applicable detection patterns in the whole chapter.

## What the four-question filter looks like in practice

A real triage session, with 6 candidates and my answers:

| Candidate | Q1 (boundary) | Q2 (generalizes) | Q3 (SOC sees) | Q4 (I learn) | Verdict |
|---|---|---|---|---|---|
| Log4Shell (CVE-2021-44228) | ✅ (HTTP header) | ✅ (JNDI lookup is general) | ✅ (every SOC monitors web) | ✅ (canonical, must understand) | **Pick** |
| Shiro RememberMe (CVE-2016-4437) | ✅ (cookie) | ✅ (Java cookie deserialize) | ✅ (web logs) | ✅ (gadget chain mechanics) | **Pick** |
| Linux kernel io_uring CVE-2024-XXXXX | ❌ (no external parsing boundary) | ✅ (kernel privesc class) | ❌ (not in logs) | ✅ | **Skip** |
| Some random JSF CVE | ✅ | ✅ | ✅ | ❌ (same as Shiro for my purposes) | **Skip** (already covered) |
| ComfyUI-Manager CRLF (CVE-2026-22777) | ✅ | ✅ (CRLF→config is general) | ✅ | ✅ (novel chain) | **Pick** |
| Some IoT router 1day | ✅ | ❌ (device-specific) | ❌ (no logs typically) | ❌ | **Skip** |

The filter is not perfect. There are CVEs that pass all four and I still skip (time budget). There are CVEs that fail one and I do anyway (career-relevant client work). But as a default queue-sorter, it produces a labour-efficient labs chapter where every entry contributes something the next entry doesn't.

## What I would tell a SOC team starting their own labs chapter

If your team has finite hours and infinite candidates:

1. **Build the rubric before you start.** It is easier to skip a CVE for failing question 1 than to abandon one 3 hours in. The filter has to be runnable on a CVE summary, not after reproduction.
2. **Weight questions 2 and 3 over question 1.** Question 1 is binary (rule it in or out). Questions 2 and 3 determine ROI on the rules you do write.
3. **Build a hunting query, not just an alert, for any question-3-weak CVE.** A hunt against a year of logs catches the attacks the live rule missed. Most teams forget this.
4. **Re-run the rubric quarterly.** A CVE that was "Q3-weak" two years ago (because nobody monitored that protocol) may have moved (because the SIEM team finally added the data source). Past-skipped is not permanently-skipped.
5. **Publish the rubric.** Your team writes better rules when the rubric is in the repo than when it's in someone's head. Mine is now in [`labs/README.md`](https://github.com/1392081456/ctf-notes/blob/main/labs/README.md) — see the "Why a separate chapter?" section for the version-1 phrasing.

---

The labs chapter is at [`ctf-notes/labs/`](https://github.com/1392081456/ctf-notes/tree/main/labs). The packaged detection content distilled from those labs is at [`sigma-detection-rules`](https://github.com/1392081456/sigma-detection-rules). The companion methodology posts on this blog cover [the four-step CVE → Sigma workflow](/2026/05/26/cve-to-sigma-30min/) and [reframing pwn writeups as defender source material](/2026/05/26/pwn-to-falco-rules/).
