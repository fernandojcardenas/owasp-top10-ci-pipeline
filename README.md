# Flagship 1: Application Security Pipeline

A small notes app with user registration, login, and per-user notes, built in three
passes:

- The [`v1` tag](../../releases/tag/v1) is the original working app with seven OWASP
  Top 10 (2021) issues deliberately seeded into it, each marked with a `VULN` comment at
  the vulnerable line.
- The default branch fixes every one of them, with a short exploit-and-fix writeup per
  vulnerability in [`docs/vulnerabilities/`](docs/vulnerabilities/README.md), including
  real before/after output for each exploit.
- A CI pipeline (`.github/workflows/security.yml`) runs SAST (Bandit plus a small
  project-specific Semgrep ruleset), SCA (`pip-audit`), and DAST (an OWASP ZAP baseline
  scan) on every push and pull request. See
  [`docs/ci-pipeline.md`](docs/ci-pipeline.md) for what each stage catches, including
  what it misses and why the other two stages are still needed.

## Running it locally

```
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
./venv/bin/python run.py
```

Then visit `http://127.0.0.1:5000/register` to create an account.

## Running the security checks locally

```
./venv/bin/pip install -r requirements-dev.txt
./venv/bin/bandit -r . -x ./venv
./venv/bin/semgrep --config security/semgrep-rules.yaml . --exclude venv
./venv/bin/pip-audit -r requirements.txt
```
