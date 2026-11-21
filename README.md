# Automated Web-Application Vulnerability Scanner

**Y23-HTE-PROJECT-150** · Cybersecurity & Blockchain Technology · Mentor: Dr. Ganta Jacob Victor

Paste any website address and get a security report. The scanner combines **OWASP ZAP**
with **custom security checks**, scores each finding by risk, and shows fix guidance in an
interactive dashboard with PDF export.

| Mode | What it does | Who can use it |
|---|---|---|
| **Quick** | Headers, cookies, HTTPS/certificate, exposed files, info leaks (~10 s) | Any URL |
| **Standard** | Quick + OWASP ZAP crawl and passive inspection of every page (~2 min) | Any URL |
| **Full** | Standard + ZAP active testing (SQL injection, XSS, ...) | Only verified owners |

> ⚠️ Active testing of a site without the owner's permission is illegal (IT Act 2000, s.43/66).
> Full scans therefore require **domain ownership verification**: the customer publishes a
> token at `https://<domain>/.well-known/vulnscanner-verify.txt` (see `scanner/verify.py`).
> Sites running on this machine (localhost) count as owned.

## Quick start

New laptop? Follow **[SETUP.md](SETUP.md)** (Windows, macOS, Linux). In short:

```bash
git clone https://github.com/SantoshReddy-hub/Chandu-Project.git vuln-scanner
cd vuln-scanner
./setup.sh      # Windows: setup.bat
./run.sh        # Windows: run.bat   → http://localhost:8501
```

## Architecture

```
Streamlit dashboard (app.py)  /  CLI (scan.py)
            │
     orchestrator.py ── URL validation (config.py) + ownership check for Full scans (verify.py)
       │            │
 zap_client.py   checks/  (headers, cookies, exposure, disclosure, transport)
 (OWASP ZAP API)    │
       └────┬───────┘
   scoring.py (dedupe + likelihood × impact → severity)
   remediation.py (CWE → fix guidance)
   storage.py (SQLite)  →  report.py (PDF)
```

| Module | Role |
|---|---|
| `scanner/zap_client.py` | Spider → passive scan → active scan via ZAP API; converts alerts to findings |
| `scanner/checks/` | Custom checks: security headers, cookie flags, sensitive file exposure, version/error disclosure, HTTPS/HSTS |
| `scanner/scoring.py` | Risk = likelihood (1-3) × impact (1-3) → Critical / High / Medium / Low / Info |
| `scanner/remediation.py` | Fix guidance per CWE |
| `scanner/storage.py` | SQLite tables `scans` and `findings` |
| `scanner/report.py` | PDF report |
| `app.py` | Dashboard: new scan, results with charts and filters, history |

## Setup

```bash
python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Start the isolated lab (needs Docker Desktop):

```bash
docker compose up -d
```

- ZAP API: http://127.0.0.1:8090
- DVWA: http://127.0.0.1:8081 (log in `admin` / `password`, click **Create / Reset Database**, set security to *Low*)
- Juice Shop: http://127.0.0.1:3000

## Run

Dashboard:

```bash
.venv/bin/streamlit run app.py
```

Command line:

```bash
.venv/bin/python scan.py example.com --mode standard
```

Modes: `quick` (no Docker needed), `standard` (ZAP crawl + passive), `full` (ZAP active, verified sites only).

In the dashboard, type or paste the address into **Enter URL** (`https://` is added automatically), or click a **demo target** button (🎯 DVWA or 🎯 OWASP Juice Shop) to fill in a local lab app. Demo targets count as owned, so all three modes, including Full, work on them.

Without Docker, try the bundled misconfigured test site:

```bash
.venv/bin/python lab/test_target.py
```

```bash
.venv/bin/python scan.py http://127.0.0.1:8099 --mode quick
```

## Validation plan

1. Write down the known vulnerabilities in DVWA and Juice Shop (ground truth).
2. Run `full` scans; mark each finding as TP or FP and list missed ones (FN).
3. Report Precision = TP/(TP+FP), Recall = TP/(TP+FN), F1, scan time.
4. Compare **ZAP alone** vs **ZAP + custom checks** (the dashboard's "ZAP vs custom checks" chart).

## Future scope

- Store report hashes on a blockchain for tamper-proof audit trails
- CI/CD integration (GitHub Actions)
- Authenticated multi-role access-control testing
- ML-based false-positive reduction
