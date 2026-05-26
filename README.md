# 1392081456.github.io

Personal blog of **Colorful White** — defensive security research notes.

Built with Jekyll + the `minima` theme. GitHub Pages auto-builds on push to `main`.

Live site: <https://1392081456.github.io>

## Local development (optional)

```sh
bundle install
bundle exec jekyll serve --livereload
# browse http://localhost:4000
```

You do not need to run Jekyll locally for the site to publish — GitHub Pages will build any push to `main` automatically.

## Adding a post

Drop a markdown file under `_posts/` with the filename pattern `YYYY-MM-DD-slug.md` and the standard Jekyll front matter:

```yaml
---
layout: post
title: "Post title"
date: 2026-05-26 09:00:00 +0800
categories: [detection-engineering]
tags: [sigma, suricata]
---
```
