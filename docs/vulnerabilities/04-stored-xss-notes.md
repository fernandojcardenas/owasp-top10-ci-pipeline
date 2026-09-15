# Stored XSS in note content

**OWASP category:** A03:2021 Injection
**CWE:** CWE-79 Improper Neutralization of Input During Web Page Generation
**Location:** `app/templates/note_view.html`

## The vulnerability

Jinja2 auto-escapes variables by default, but the note template explicitly turned that
off for note content:

```jinja
<div>{{ note["content"] | safe }}</div>
```

The `safe` filter tells Jinja2 "trust this string, render it as raw HTML." Since note
content comes straight from user input with no sanitization, anything an attacker types
into a note body is echoed back as live HTML and JavaScript to anyone who views it,
including the note's owner and any other user the IDOR bug (or a future sharing feature)
exposes it to.

## Exploit

Create a note whose content is a script tag, then fetch the page and look at the raw
response body:

```
$ curl -c alice.txt -b alice.txt \
    -d "title=Secret&content=<script>alert(1)</script>" \
    http://127.0.0.1:5000/notes

$ curl -c alice.txt -b alice.txt http://127.0.0.1:5000/notes/1
<h1>Secret</h1>
<div><script>alert(1)</script></div>
```

The `<script>` tag comes back completely unescaped. In a browser this executes
immediately on page load; a real payload would read `document.cookie` or the page's DOM
and send it to an attacker-controlled endpoint, rather than just popping an alert.

## Fix

Remove the `safe` filter and let Jinja2's default auto-escaping do its job:

```jinja
<div>{{ note["content"] }}</div>
```

## Verification

```
$ curl -c alice.txt -b alice.txt http://127.0.0.1:5000/notes/1
<h1>Secret</h1>
<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>
```

The tag is now rendered as literal, inert text (`&lt;script&gt;...&lt;/script&gt;`)
instead of being interpreted as markup, so it displays as text and never executes.
