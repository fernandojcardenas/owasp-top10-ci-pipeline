# CI security pipeline

`.github/workflows/security.yml` runs three jobs on every push and pull request:
SAST, SCA, and DAST. All three block a pull request from merging if they fail.

## SAST: Bandit + a small custom Semgrep ruleset

Bandit catches three of this app's seven seeded bugs out of the box. Run against the
vulnerable v1 code:

```
$ bandit -r . -x ./venv
>> B105 hardcoded_password_string   app/__init__.py:5   (the SECRET_KEY literal)
>> B506 yaml_load                   app/config_loader.py:12
>> B608 hardcoded_sql_expressions   app/models.py:47
```

It does not catch the IDOR (business logic, not a syntax pattern), the plaintext
password storage (there's no unsafe call to flag, just a hash call that's missing), the
stored XSS (Jinja templates aren't in Bandit's scope), or `debug=True` in `run.py`.
That last miss is worth a closer look: Bandit's `B201` check does flag `debug=True` when
the `Flask(...)` constructor is visible in the same file, but this app uses the
app-factory pattern (`app = create_app()` in a different module), and Bandit doesn't
trace across files to know `app` is a Flask instance. A quick test confirms it:

```python
# flags: Flask() and .run(debug=True) in the same file
from flask import Flask
app = Flask(__name__)
app.run(debug=True)          # Bandit: B201, High

# does NOT flag: app comes from an imported factory function
from app import create_app
app = create_app()
app.run(debug=True)          # Bandit: nothing
```

`security/semgrep-rules.yaml` is five rules written for this codebase specifically to
close gaps like that one, plus catch the stored XSS that no Python-focused tool would
ever see:

- `flask-debug-true-any-receiver`: matches `$APP.run(..., debug=True, ...)` regardless
  of where `$APP` came from, closing the exact gap above.
- `sql-query-fstring-taint`: a taint-mode rule (source: any f-string/`.format`/`%`
  string, sink: `.execute(...)`) so it catches the query even though it's built on one
  line and executed on another, rather than requiring both in the same expression.
- `unsafe-yaml-load`: flags `yaml.load()` unless it can see it's using a safe loader.
- `hardcoded-flask-secret-key`: flags a literal string assigned to `SECRET_KEY` or
  `app.config["SECRET_KEY"]`.
- `jinja-unsafe-filter`: a regex rule scoped to `.html`/`.jinja` files that flags the
  `| safe` filter, since Semgrep's structural Jinja matching didn't reliably bind an
  expression like `note["content"] | safe` and a plain regex turned out to be the more
  reliable tool for this one file type.

Bandit and Semgrep together catch five of the seven seeded bugs. The remaining two
(IDOR, plaintext passwords) are exactly the kind of thing SAST structurally can't see:
missing authorization logic and a missing security control, not a dangerous pattern that
is present. That gap is why this pipeline also has a DAST stage and why the project
still needs a human reading the exploit writeups in `docs/vulnerabilities/`, not just a
green CI check.

## SCA: pip-audit

`pip-audit -r requirements.txt` checks every pinned dependency against the Python
Packaging Advisory Database. Run against v1's pins it found 12 distinct advisories
across Flask and Werkzeug, only one of which I'd gone in already knowing about; see
`docs/vulnerabilities/06-outdated-werkzeug-cve.md` for the full output and the versions
that clear it.

## DAST: OWASP ZAP baseline scan

The `dast` job starts the app in the CI runner and points
[`zaproxy/action-baseline`](https://github.com/zaproxy/action-baseline) at it. ZAP
crawls the running app and passively checks the live HTTP traffic and responses (missing
security headers, cookie flags, server banners, and similar), which is a useful
complement to SAST precisely because it's exercising the real running app instead of
reading source, and needs no knowledge of what the code looks like. It runs last
(`needs: [sast, sca]`) since there's no point spinning up the app if the static checks
already failed.

The first real run of this pipeline on GitHub caught something neither Bandit nor
Semgrep did, since neither one looks at HTTP responses at all:

```
WARN-NEW: Missing Anti-Clickjacking Header [10020] x4
WARN-NEW: X-Content-Type-Options Header Missing [10021] x4
WARN-NEW: Server Leaks Version Information via "Server" HTTP Response Header Field [10036] x5
WARN-NEW: Cross-Origin-Embedder-Policy Header Missing or Invalid [90004] x9
FAIL-NEW: 0    WARN-NEW: 11    PASS: 56
```

None of the seeded OWASP bugs themselves triggered anything, which is a live confirmation
that the fixes in `docs/vulnerabilities/` hold up under an actual scan of the running
app, not just against the specific exploit commands I used. But the app also wasn't
setting any hardening headers at all. The fix, in `app/__init__.py`, is an
`after_request` hook that sets `X-Frame-Options`, `X-Content-Type-Options`, and
`Cross-Origin-Embedder-Policy`. The "Server" header needed a second fix: Werkzeug's
development server adds its own version banner at the socket level regardless of what
the Flask app sets in its response, so `run.py` also overrides
`WSGIRequestHandler.version_string()` to stop the interpreter and framework version from
being broadcast on every response. (In a real deployment behind gunicorn or a reverse
proxy this particular quirk wouldn't come up the same way, since neither adds an
unconditional version banner the app can't override, but this app runs its own dev
server in CI, so it needed the explicit fix.)

The first CI run also failed for an unrelated reason: `zaproxy/action-baseline`
tries to file a GitHub issue with its findings by default, which needs `issues: write`
permission that the default workflow token doesn't have, so that step 403'd separately
from the actual scan result. Fixed by setting `allow_issue_writing: false`; the job's
pass/fail status and the log output are the signal this pipeline actually relies on, not
an auto-filed issue on every run.

Fixing those four headers didn't clear the job, it just uncovered the next layer: ZAP
re-crawled the now-hardened responses and surfaced eight more findings that were sitting
behind the noise of the first batch:

```
WARN-NEW: Content Security Policy (CSP) Header Not Set [10038] x3
WARN-NEW: Non-Storable Content [10049] x7
WARN-NEW: Cookie without SameSite Attribute [10054] x1
WARN-NEW: Permissions Policy Header Not Set [10063] x5
WARN-NEW: Authentication Request Identified [10111] x1
WARN-NEW: Session Management Response Identified [10112] x1
WARN-NEW: Absence of Anti-CSRF Tokens [10202] x4
WARN-NEW: Cross-Origin-Opener-Policy Header Missing or Invalid [90004] x8
FAIL-NEW: 0    WARN-NEW: 8    PASS: 59
```

Two of these aren't findings at all: `10111` and `10112` are ZAP noting "this looks like
a login endpoint" and "this response sets a session cookie", informational markers with
no fix to apply. Those are suppressed with `.zap/rules.tsv`
(`rules_file_name` in the workflow), which is the correct way to tune a DAST tool, telling
it what you've already reviewed and judged not actionable, rather than either failing the
build on noise or silently lowering `fail_action` for everything.

The rest were real gaps, fixed as follows:

- `Content-Security-Policy: default-src 'self'` and a `Permissions-Policy` header
  disabling APIs the app never uses, added in the same `after_request` hook as the first
  batch.
- `Cross-Origin-Opener-Policy: same-origin` alongside the `Cross-Origin-Embedder-Policy`
  from the first pass; the same ZAP rule ID (`90004`) flags either header when it's
  missing, which is why it showed up twice under one number across two runs.
- `Cache-Control: no-store` on every response, since this app has no public pages, every
  response is private per-user data that shouldn't be cached.
- `SESSION_COOKIE_SAMESITE = "Lax"` in the Flask config, so the session cookie is never
  attached to a cross-site request in the first place.
- Anti-CSRF tokens, via Flask-WTF's `CSRFProtect`: every POST form now includes a
  per-session token, and a POST without a valid one is rejected with 400 before it ever
  reaches a route. Verified locally: a login POST missing the token returns 400, and the
  full register/login/create-note flow succeeds when the token is scraped out of the form
  first, the way a real browser submission would.

That still didn't clear the job. The third run turned up four more findings, each one
closing a loose end the previous fixes had left:

```
WARN-NEW: User Controllable HTML Element Attribute (Potential XSS) [10031] x1
WARN-NEW: Non-Storable Content [10049] x5
WARN-NEW: CSP: Failure to Define Directive with No Fallback [10055] x5
WARN-NEW: Cross-Origin-Resource-Policy Header Missing or Invalid [90004] x4
FAIL-NEW: 0    WARN-NEW: 4    INFO: 0    IGNORE: 2    PASS: 61
```

(`IGNORE: 2` here confirms the `.zap/rules.tsv` suppression from the previous fix is
working, and `90004` shows up a third time for the same reason it showed up twice
before: that one ZAP rule checks three separate headers together, Cross-Origin-Embedder-
Policy, Cross-Origin-Opener-Policy, and Cross-Origin-Resource-Policy, and reports whichever
one is still missing.)

Two of these needed a real header fix:

- `10055`: per the CSP spec, `frame-ancestors`, `object-src`, and `base-uri` don't fall
  back to `default-src` the way most fetch directives do, so a bare `default-src 'self'`
  leaves them unset. The policy now lists all four directives explicitly.
- `90004`: added `Cross-Origin-Resource-Policy: same-origin` alongside the other two.

The other two turned out not to be real findings, which is a distinction worth making
explicit rather than fixing blindly:

- `10049` (Non-Storable Content) sounds like a problem but isn't one here. Reading ZAP's
  own rule description: it flags responses that *aren't* cacheable and suggests adding
  cache headers to *improve performance*, on the assumption most content benefits from
  caching. This app already sends `Cache-Control: no-store` on purpose, since every
  response is private, per-user data; making it cacheable to satisfy this rule would be
  the wrong tradeoff, not a fix. Suppressed with a comment explaining why.
- `10031` (User Controllable HTML Element Attribute) is genuinely informational, ZAP's
  own docs call it a "hot spot requiring human review," not a confirmed issue. I checked
  by hand: no template in this app reflects a query parameter or any other request input
  into an HTML attribute (verified by requesting `/login?username=test` and inspecting
  the rendered output). The only dynamic attribute value on that page is the CSRF token,
  which is server-generated and signed, not something an attacker controls. Suppressed
  with the reasoning recorded in `.zap/rules.tsv` rather than left unexplained.

This is the actual shape of tuning a DAST tool for a real pipeline: some findings need a
code fix, and some need a documented, reviewed decision that they don't apply, recorded
in the rules file so the next person (or the next run) doesn't have to re-litigate it
from scratch.

Adding `object-src`, `base-uri`, and `frame-ancestors` didn't fully clear rule 10055
either; it kept firing on a single remaining gap. Reading ZAP's own scan rule source
(`ContentSecurityPolicyScanRule.java`) rather than guessing again: the rule checks
exactly two directives against this fallback issue, `frame-ancestors` and `form-action`,
nothing else. I had the first but not the second, so the policy now also lists
`form-action 'self'`. Fourth run, zero warnings.

## Why three tools instead of one

Each layer has a different blind spot: SAST reads source but can't see missing
authorization logic; SCA knows nothing about this app's own code, only what's declared
in `requirements.txt`; DAST sees the running app's behavior but nothing about why the
code produces it. Together they cover far more than any one of them alone, which is the
actual argument for running all three on every pull request rather than picking one.
