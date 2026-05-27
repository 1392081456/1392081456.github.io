---
layout: page
title: Topics
permalink: /topics/
wide: true
---

Posts are grouped by **category** (broad subject area) and indexed by **tag**
(specific tool, technique, or artifact). Both link back to the same posts; pick
whichever entry point is more useful.

## By category

{% assign sorted_cats = site.categories | sort %}
{% for cat in sorted_cats %}
<section class="topic-group" id="cat-{{ cat[0] | slugify }}">
  <h2>{{ cat[0] }}</h2>
  <ul class="post-list">
    {% assign cat_posts = cat[1] | sort: 'date' | reverse %}
    {% for post in cat_posts %}
      <li>
        <div class="post-meta">
          <time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: "%Y-%m-%d" }}</time>
        </div>
        <h2 class="post-title">
          <a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a>
        </h2>
      </li>
    {% endfor %}
  </ul>
</section>
{% endfor %}

## By tag

{% assign sorted_tags = site.tags | sort %}
<section class="topic-group">
  <ul>
    {% for tag in sorted_tags %}
      <li id="tag-{{ tag[0] | slugify }}">
        <strong>{{ tag[0] }}</strong> &mdash;
        {% assign tag_posts = tag[1] | sort: 'date' | reverse %}
        {% for post in tag_posts %}
          <a href="{{ post.url | relative_url }}">{{ post.title | escape | truncate: 60 }}</a>{% unless forloop.last %};{% endunless %}
        {% endfor %}
      </li>
    {% endfor %}
  </ul>
</section>
