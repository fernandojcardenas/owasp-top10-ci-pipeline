# Vulnerable and outdated components: Flask and Werkzeug

**OWASP category:** A06:2021 Vulnerable and Outdated Components
**CWE:** CWE-1104 Use of Unmaintained Third Party Components
**Location:** `requirements.txt`

## The vulnerability

`requirements.txt` pinned `Flask==2.2.2` and `Werkzeug==2.2.2`. Neither is a coding
mistake in this app's own code; both are known-vulnerable versions of a pinned
dependency, which is exactly what an SCA (software composition analysis) scanner is for.
Running `pip-audit` against the v1 pins turned up far more than the one CVE I already
knew about (CVE-2023-25577, an unbounded multipart form parser that enables a
denial-of-service):

```
$ pip-audit -r requirements.txt
Found 22 known vulnerabilities in 2 packages
Name     Version ID              Fix Versions
-------- ------- --------------- ------------
flask    2.2.2   PYSEC-2023-62   2.2.5,2.3.2
flask    2.2.2   PYSEC-2026-2151 3.1.3
werkzeug 2.2.2   PYSEC-2023-57   2.2.3
werkzeug 2.2.2   PYSEC-2023-58   2.2.3
werkzeug 2.2.2   PYSEC-2023-221  2.3.8,3.0.1
werkzeug 2.2.2   PYSEC-2026-2043 3.0.3
werkzeug 2.2.2   PYSEC-2026-2045 3.0.6
werkzeug 2.2.2   PYSEC-2026-1860 3.0.6
werkzeug 2.2.2   PYSEC-2026-2046 3.1.4
werkzeug 2.2.2   PYSEC-2026-2044 3.1.5
werkzeug 2.2.2   PYSEC-2026-2320 3.1.6
werkzeug 2.2.2   PYSEC-2026-3417 3.0.6
```

(each id is listed twice by the tool; the distinct advisories are as shown). This is the
real lesson SCA teaches that manual review doesn't: new advisories get filed against old
pins on a rolling basis, so "I checked once" is not the same as "this is safe." A pin
that was fine last quarter can be sitting on a disclosed vulnerability today with no
change to the app's own code at all.

## Exploit

I did not reproduce any of these live. Several are denial-of-service class bugs (crafted
requests that make the server spend excessive CPU/memory), and re-deriving a known DoS
against even a disposable local instance isn't worth the risk for the marginal value of
proving a publicly-documented advisory is real. The value here is catching this
automatically, which is exactly what the SCA job in `.github/workflows/security.yml`
does, on this app and on every future dependency bump.

## Fix

An initial, minimal fix (bumping only `Werkzeug` to `2.2.3`) closed the original CVE I
knew about, but `pip-audit` showed that wasn't enough: 18 advisories remained even after
that bump, because most of them were filed after 2.2.3. The actual fix moves onto
currently-maintained release lines:

```
Flask==3.1.3
Werkzeug==3.1.6
```

The full register/login/create-note/view-note flow was re-run against these versions
with zero code changes required; Flask 3.x kept every API this app uses (blueprints,
`session`, `render_template`, the app-factory pattern) unchanged.

## Verification

```
$ pip-audit -r requirements.txt
No known vulnerabilities found
```
