---
layout: post
title: "File Upload Is a Four-Stage Boundary"
date: 2026-06-30 09:30:00 +0800
categories: [web-security, methodology, detection-engineering]
tags: [file-upload, validation, race-condition, portswigger]
related_posts:
  - deserialization-restores-code-paths
  - path-traversal-is-a-canonicalization-bug
  - business-logic-bugs-are-broken-invariants
---

File upload vulnerabilities are not just extension bypasses. An upload feature has at least four security stages:

```text
upload -> store -> serve -> execute
```

The seven PortSwigger labs show that breaking any one of those boundaries can be enough.

This series was re-run and live-verified on 2026-05-30 as 7/7 solved. The
polyglot case used a valid JPEG metadata segment containing PHP, and the race
case was won by pairing repeated uploads with high-rate reads of the public
avatar path.

## MIME is not validation

The simple cases accept a PHP file directly, or trust the request's multipart MIME type:

```http
Content-Disposition: form-data; name="avatar"; filename="exploit.php"
Content-Type: image/jpeg
```

The filename still ends in `.php`. The server-side handler, not the upload form, decides whether code is interpreted.

## Storage path matters

One lab blocks execution in `/files/avatars`, but the filename is decoded and joined unsafely:

```http
filename="..%2fexploit.php"
```

The file is stored one directory higher, where PHP execution is enabled.

The durable lesson is that validation must happen after canonicalization. Check the final path, not the string before decoding.

## Blacklists miss handlers

Blocking `.php` is not enough if the directory lets attackers upload configuration:

```apache
AddType application/x-httpd-php .l33t
```

Now `exploit.l33t` is executable. Blacklists fail because execution is a server configuration question, not just a filename question.

## Polyglots pass content checks

Content checks can still fail when the file is valid in two formats. JPEG metadata can contain PHP:

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" input.jpg -o polyglot.php
```

An image parser sees an image. A PHP parser sees PHP. Re-encoding images and stripping metadata is stronger than trusting the original bytes.

## Timing is a boundary

The race-condition lab is the most important operational lesson:

```php
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);
if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "uploaded";
} else {
    unlink($target_file);
}
```

The file is public before validation finishes. One request uploads repeatedly; another fetches repeatedly. The right fix is not a faster scanner. The fix is quarantine first, public move after validation.

## Defender notes

Hardening:

- store uploads outside the webroot;
- generate filenames server-side;
- normalize before extension checks;
- use extension allowlists, not blacklists;
- validate MIME, magic bytes, and decoded content;
- re-encode images and strip metadata;
- disable script execution and `.htaccess` overrides in upload directories;
- validate in a private quarantine area, then atomically move approved files.

Detection:

- uploads with `.php`, `.phtml`, `.phar`, `.htaccess`, double extensions, `%00`, or traversal;
- mismatch between extension, MIME, and magic bytes;
- PHP tags inside metadata;
- immediate high-rate GETs for just-uploaded files;
- executable responses from upload directories;
- `.htaccess` files containing handler directives.

File upload safety is not one check. It is the consistency of every stage from bytes entering the server to bytes leaving it again.
