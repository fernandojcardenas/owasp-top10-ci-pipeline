# Vulnerability writeups

Each file here documents one issue seeded into the v1 baseline: what the vulnerability
was, a reproducible exploit against v1 with real output, the fix applied afterward, and a
re-run of the same exploit against the fixed code to confirm it no longer works.

| # | Vulnerability | OWASP category |
|---|---|---|
| 1 | [IDOR on note access](01-idor-note-access.md) | A01 Broken Access Control |
| 2 | [Plaintext password storage](02-plaintext-passwords.md) | A02 Cryptographic Failures |
| 3 | [SQL injection in login](03-sql-injection-login.md) | A03 Injection |
| 4 | [Stored XSS in note content](04-stored-xss-notes.md) | A03 Injection |
| 5 | [Hardcoded SECRET_KEY and debug mode](05-hardcoded-secret-and-debug-mode.md) | A05 Security Misconfiguration |
| 6 | [Outdated Werkzeug (CVE-2023-25577)](06-outdated-werkzeug-cve.md) | A06 Vulnerable and Outdated Components |
| 7 | [Insecure YAML deserialization](07-insecure-yaml-deserialization.md) | A08 Software and Data Integrity Failures |

All of these are fixed on the default branch. The [`v1` tag](../../releases/tag/v1)
still has the original vulnerable code for anyone who wants to reproduce an exploit
against it.
