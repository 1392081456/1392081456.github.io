---
layout: page
title: About
permalink: /about/
---

# About

I am **Colorful White**, an independent defensive-security researcher affiliated with the **Guangdong University of Technology (GDUT)**.

## Research

- **Adversarial machine learning** — first author of:
  *Data-Free Black-Box Adversarial Attack Method Based on GAN*, *Computer Engineering and Applications*, 2025, 61(7): 204.
  [DOI: 10.3778/j.issn.1002-8331.2311-0227](https://doi.org/10.3778/j.issn.1002-8331.2311-0227).
  The journal is indexed in the Peking University Core Journals catalogue and the CSCD. The DOI page resolves to both Chinese full text and the publisher's official English abstract + keywords.

- **Detection engineering** — I reproduce published CVEs in isolated vulhub Docker containers and translate each one into the canonical SOC artifact set:
  - **Sigma** YAML detection rule
  - **Suricata** signature with reserved SID block
  - **Structured IOC table** (file hashes, URI patterns, command-line strings, network indicators)
  - **Hunting queries in multiple SIEM dialects** — Splunk SPL, Microsoft Sentinel KQL, Elastic ES|QL

  Twenty-three CVEs are currently catalogued in [ctf-notes/labs](https://github.com/1392081456/ctf-notes/tree/main/labs), covering Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965), Shiro RememberMe (CVE-2016-4437), ActiveMQ OpenWire (CVE-2023-46604) and Jolokia (CVE-2026-34197), Jenkins CLI (CVE-2024-23897), Grafana DuckDB (CVE-2024-9264), TeamCity (CVE-2024-27198), and others.

## CTF practice

- Member of team **APWN** ([CTFtime team page](https://ctftime.org/team/435891), [my profile](https://ctftime.org/user/261101))
- ~30 highlighted deep writeups + ~344 catalogued entries across pwn, reverse engineering, cryptography, web exploitation, forensics, and the labs chapter — see [`ctf-notes`](https://github.com/1392081456/ctf-notes)

## Authorship and AI assistance

I am the sole author and decision-maker on every artifact published here and in the linked repositories. Large language models (primarily Claude) are used as research, translation, and drafting assistants — **all exploit logic, vulnerability analysis, detection-rule design, and methodological choices are designed, verified, and signed off by me.** Where commits in my repositories carry a `Co-Authored-By: Claude` trailer, that trailer is a transparency disclosure of AI assistance, not an attribution of intellectual authorship.

## Scope statement

All research is conducted on (a) public CTF challenge binaries distributed by event organizers, (b) vulhub Docker images of vendor-patched CVEs run on `127.0.0.1` in isolation with no external network access, (c) virtual machines I own on hardware I own, or (d) academic research code I author. **No production system, third-party service, or unauthorized network is involved at any stage.** The intent of this work is consistently defensive — understanding offensive techniques deeply enough to detect them, patch them, and write durable security controls.

## Contact

- Email — `colorfulwhitez@gmail.com`
- GitHub — [@1392081456](https://github.com/1392081456)
- CTFtime — [@colorfulwhitez](https://ctftime.org/user/261101)
