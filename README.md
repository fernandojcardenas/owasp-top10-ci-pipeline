# Flagship 1: Application Security Pipeline

A small notes app with user registration, login, and per-user notes, built in two
passes:

- `master` holds v1, a working app with seven OWASP Top 10 (2021) issues deliberately
  seeded into it, each marked with a `VULN` comment at the vulnerable line.
- `hardened` (this branch) fixes every one of them, with a short exploit-and-fix writeup
  per vulnerability in [`docs/vulnerabilities/`](docs/vulnerabilities/README.md),
  including real before/after output for each exploit.

Next up: a CI pipeline running SAST, SCA, and DAST checks on every pull request, so this
class of bug gets caught automatically instead of by manual review.

## Running it locally

```
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python run.py
```

Then visit `http://127.0.0.1:5000/register` to create an account.
