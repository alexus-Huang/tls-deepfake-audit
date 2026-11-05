# TLS Deepfake Audit

CMPM118 project: a probing tool that audits the TLS/cryptographic setup of web hosts, built to compare a benign baseline (Tranco top domains) against domains associated with deepfake scams and phishing.

**Research question:** do malicious deepfake-related hosts show structural TLS weaknesses (deprecated protocols, short-lived certificates, missing CAA records) compared to standard web infrastructure?

## Status

- Working: dataset builder, safety-limited scanner (certificate info + TLS 1.3 cipher suites), and a four-library comparison harness.
- Tested so far on a **10-domain benign sample only** (example.com plus the top 9 Tranco domains).
- Not done yet: scanning threat-intel domains. Waiting on dataset provided by Naate.
- 61 unit tests, none of which touch the network.

## Safety limits (enforced in code)

All scans go through `ScanConfig` (`src/tlsaudit/config.py`), which refuses values above these ceilings.

| Limit | Value |
|---|---|
| Hosts scanned in parallel | max 5 |
| Connections per host | max 2 |
| Connect timeout | 5 s (ceiling 10 s) |
| Attempts per connection | 1 (no retries) |

Other safeguards:
- Only plain hostnames on port 443 are accepted. IP addresses, URLs, ports, and `localhost` are rejected.
- Scan commands come from an allowlist: certificate info and cipher suites only. Vulnerability probes (Heartbleed, CCS injection, ROBOT, renegotiation) and deprecated-protocol cipher scans are blocked, and tests enforce this.
- TLS 1.2 cipher enumeration (up to 158 attempts per host) exists as an opt-in but is not used. Nate advised sticking to TLS 1.3.
- The curl_cffi probe sends one HEAD request per host, with no redirects, no retries, and no body download.
- check-tls runs with crt.sh, CRL, OCSP, and HSTS checks disabled, so it contacts no third parties and sends no HTTP request to the site.

## Ethics and approval

- This is **active measurement**. Nate approved it in an email (see `docs/ERROR_LOG.md`).
- No exploiting, logging in, fuzzing, or content downloading. Scanned domains are never opened in a browser.
- Raw threat feeds and scan output are excluded from the repository (`.gitignore`). Malicious domains must be defanged (`evil[.]com`) in anything shared.
- Every scan is recorded in the scan log in `docs/ERROR_LOG.md`.
- If a site operator or network administrator contacts the researcher, scanning stops.

## Project layout

```
src/tlsaudit/
  config.py         safety limits (ScanConfig)
  dataset.py        domain cleaning, Tranco loader, composite dataset
  scan_settings.py  turns ScanConfig into SSLyze settings; scan-command allowlist
  scanner.py        Tier 1 scanner: certificate info + TLS 1.3 ciphers -> JSON Lines
  compare.py        compares SSLyze, ssl, curl_cffi, check-tls on the same domains
tests/              61 unit tests (no network)
docs/               error log, scan log, approval screenshots
data/raw/           Tranco list, threat feeds (not committed)
data/results/       scan output (not committed)
```

## Setup (Windows, cmd)

Requires Python 3.10+ (tested on 3.12.2).

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

check-tls runs from its own venv, so its dependencies stay isolated:

```bat
py -3.12 -m venv .venv-checktls
.venv-checktls\Scripts\python -m pip install check-tls==1.10.0
```

## Data

1. Download the Tranco list from https://tranco-list.eu, extract it, and save it as `data\raw\top-1m.csv` (format: `rank,domain`). Record the list ID in your report. [Tranco list ID: fill in]
2. Threat-intel domain lists go in `data\raw\threat_deepfake.txt` and `data\raw\threat_phishing.txt`, one domain per line. They are not committed, and none have been scanned yet.

## Running

```bat
set PYTHONPATH=src
python -m pytest -v
python -c "from tlsaudit.scanner import scan_domains; scan_domains(['example.com'], 'data/results/tier1_test.jsonl')"
python -m tlsaudit.compare
```

`scan_domains` appends to its output file, so delete the old file before rerunning. `python -m tlsaudit.compare` asks you to type `YES` before sending any traffic.

## Results so far (10 benign domains)

- 8 of 10 completed in every library. `ezviz7.com` and `akamai.net` failed DNS resolution in all four, so the failure is a property of the names.
- All 8 hosts accepted the same 3 of 5 TLS 1.3 cipher suites, so TLS 1.3 alone gives little separation between hosts.
- Certificate validity ranged from 83 to 197 days. 6 of 8 hosts publish CAA records.

| Library | Seconds (10 domains) | Sec/host | 100k hosts (hours, best case) |
|---|---|---|---|
| SSLyze | 1.80 | 0.180 | 5.0 |
| ssl (stdlib) | 0.47 | 0.047 | 1.3 |
| curl_cffi | 0.35 | 0.035 | 1.0 |
| check-tls | 2.39 | 0.239 | 6.6 |

These are best-case estimates from 8 large, fast sites. Real runs include slow and dead hosts. check-tls timing includes process start-up, so it isn't like-for-like.

## Library comparison (summary)

| Library | Lists all accepted ciphers | What it adds |
|---|---|---|
| SSLyze | **Yes** (one connection per cipher) | Certificate and cipher detail |
| ssl | No (negotiated cipher only) | Fast, built-in baseline |
| check-tls | No (negotiated cipher only) | CAA records, certificate fields |
| curl_cffi | No | HTTP response seen with a browser fingerprint |

nassl was excluded because it is SSLyze's own engine and is described by its author as experimental.

## Limitations

- Benign sample only, ten domains. No claim about malicious hosts yet.
- TLS 1.3 only, so deprecated-protocol support cannot be tested at this scope.
- Many hosts sit behind shared infrastructure (for example Cloudflare), so results can reflect the host provider and not the site operator.
- The scanner resolves DNS one domain at a time, which will not scale to 100k hosts, and it has no resume support. Both are planned.
- The same host can return slightly different certificates between probes (observed on facebook.com).

## AI assistance
The project plan was drafted with an AI assistant, and an AI model helped with guidance, code and learning new topics I've never encountered. I ran and tested everything, and `docs/ERROR_LOG.md` records where AI-generated guidance was wrong.

## Docs

`docs/ERROR_LOG.md` holds the error log, approval record, and scan log.