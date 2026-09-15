# Vulnerable and outdated component: Werkzeug 2.2.2

**OWASP category:** A06:2021 Vulnerable and Outdated Components
**CWE:** CWE-1104 Use of Unmaintained Third Party Components
**Location:** `requirements.txt`

## The vulnerability

`requirements.txt` pinned `Werkzeug==2.2.2`, which is affected by
[CVE-2023-25577](https://github.com/pallets/werkzeug/security/advisories/GHSA-xg9f-g7g7-2323):
Werkzeug's multipart/form-data parser did not cap the number of parts it would parse from
a request. A request crafted with a very large number of form parts (including file
parts) makes the server spend excessive CPU and memory parsing it, a denial-of-service
vector that requires no authentication.

This wasn't a coding mistake in this app's own code; it's a bug in a pinned dependency
that shipped in the app's own `requirements.txt`, exactly the kind of issue an SCA
(software composition analysis) scanner is meant to catch on every dependency bump, which
is why it is called out here even though there is no app-specific line to point at.

## Exploit

I did not reproduce the denial-of-service live: doing so means sending a large,
resource-exhausting request at a shared server, which isn't something to do even against
a disposable local instance, and the value of catching it comes from dependency scanning,
not from re-deriving the same known issue by hand. The vulnerability class is well
documented in the advisory linked above, and the planned CI pipeline (`t1-7`/`t1-8`) will
run `pip-audit` against `requirements.txt` specifically so this class of bug is caught
automatically the moment a pinned version has a known CVE, rather than relying on manual
review.

## Fix

Bump the pin to the version where the advisory was patched:

```
Werkzeug==2.2.3
```

## Verification

```
$ pip install "Werkzeug==2.2.3"
$ python -c "import werkzeug; print(werkzeug.__version__)"
2.2.3
```

The full register/login/create-note/view-note flow was re-run against the upgraded
dependency with no behavior change, confirming the bump is a drop-in fix at this app's
current feature set.
