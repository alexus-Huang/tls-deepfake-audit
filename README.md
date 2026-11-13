# TLS Probing and Library Comparison Tool

CMPM118 project: a safety-limited, active TLS probing tool built to answer one research question: **what TLS cipher suites are popular internet services offering?** It also includes a comparison of four Python libraries on what they return and how fast they run.

## Status

- **Working:** dataset loader with an exclusion list, safety-limited SSLyze scanner (certificate, TLS 1.3 and TLS 1.2 cipher suites), run recorder, analysis scripts, and a four-library comparison harness.
- **Measured:** 300 names from the Tranco top list (2026-11-08) and a 10-domain four-library comparison (2026-11-02), all from campus ResWiFi.
- **Tests:** 80 unit tests, none of which touch the network.
- **Not done:** larger datasets (the instructor will provide them), parallel DNS lookups, resume support.

## Results at a glance (300 names scanned)

| Outcome | Hosts |
|---|---|
| Completed | 204 (68%) |
| DNS failed | 83 (27.7%) |
| Connection error | 13 (4.3%) |

- **TLS 1.3:** 181 of 204 completed hosts accept at least one suite. Three suites are accepted by over 90% of those 181 (AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305). 23 hosts accept none, and the cause is not confirmed.
- **TLS 1.2:** all 203 scanned hosts accept at least one suite. 92.6% accept `ECDHE_RSA_WITH_AES_128_GCM_SHA256`, yet 54.7% also accept a static-RSA suite (no forward secrecy), 76.4% accept a CBC suite, and 19.2% (39 hosts) still accept 3DES. Only 66 distinct TLS 1.2 configurations exist among the 203 hosts.
- **Certificates:** validity ranged from 29 to 397 days. Seven operators (Google Trust Services, DigiCert, Let's Encrypt, Amazon, GlobalSign, Sectigo, Microsoft) issued about 90% of the certificates.
- **Run time:** 468 s for 300 names (1.56 s per host), about 43 hours per 100,000 hosts at this mix. A rough estimate, not a measurement at scale.

Full tables and caveats are in `docs/RESULTS.md`. These are host counts. Hosts share operators and CDN configurations, so they are not independent observations.

## How it works

1. `dataset.py` cleans domain names, applies the exclusion list, and loads a list in chunks.
2. `config.py` holds the safety limits, and `scan_settings.py` turns them into SSLyze settings.
3. `scanner.py` runs SSLyze and writes one JSON line per host. Failures are recorded as data and never retried.
4. `runner.py` runs a scan and saves it in its own folder with a `run.json` record (network, settings, timing, outcome counts).
5. `summarize.py` builds a timing table across runs, and `analyze.py` counts the suites hosts accept.
6. `compare.py` runs the same domains through SSLyze, Python's `ssl`, curl_cffi, and check-tls.

## Safety and ethics

All scans go through `ScanConfig`, which refuses values above these ceilings.

| Limit | Value |
|---|---|
| Hosts scanned in parallel | max 5 |
| Connections per host | max 2 |
| Connect timeout | 3 s used (ceiling 10 s) |
| Attempts per connection | 1 (no retries) |

- **Approval:** active measurement, the plan, and the limits were approved by the instructor in writing. The TLS 1.2 scope, the timeout tests, and the roughly 300-domain run followed guidance from a meeting with the instructor (verbal).
- **No exploiting, logging in, fuzzing, or downloading.** Only plain hostnames on port 443 are accepted. An allowlist limits SSLyze to certificate and cipher-suite scans, and vulnerability probes (Heartbleed, CCS injection, ROBOT, renegotiation) and deprecated-protocol scans are blocked and covered by tests.
- **Exclusion list** (`data/raw/exclude.txt`): 17 names were excluded at my own discretion: government sites, DNS root and TLD infrastructure, and 10 unrecognized names. Excluding by appearance adds a small selection bias.
- **Load:** with TLS 1.2, each host receives about 164 short handshake attempts, at most 2 open at once. The scans were run in chunks of 100.
- **Never opened in a browser.** Raw lists and scan output are gitignored. Every run is recorded in `docs/ERROR_LOG.md` (scan log) and in a `run.json` file.
- If a site operator or network administrator makes contact, scanning stops and the instructor is told.

## Project layout

```
src/tlsaudit/
  config.py         safety limits (ScanConfig)
  dataset.py        domain cleaning, loaders, exclusion list
  scan_settings.py  ScanConfig -> SSLyze settings; scan-command allowlist
  scanner.py        SSLyze scanner -> JSON Lines
  runner.py         command-line runner; saves each run in its own folder
  summarize.py      timing table across runs
  analyze.py        counts of accepted suites, issuers, validity
  compare.py        four-library comparison harness
tests/              80 unit tests (no network)
docs/               ERROR_LOG.md, RESULTS.md, TIMING_LOG.md, LIBRARY_COMPARISON.md
data/raw/           Tranco list, exclude.txt (not committed)
data/results/       run folders and summaries (not committed)
```

## Setup (Windows, cmd)

Requires Python 3.10+ (tested on 3.12.2).

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

check-tls runs from its own venv, so its dependencies stay isolated. This is only needed for `compare.py`:

```bat
py -3.12 -m venv .venv-checktls
.venv-checktls\Scripts\python -m pip install check-tls==1.10.0
```

## Data

Tranco list: downloaded 2026-10-28 from tranco-list.eu (the "top 1M" download). The list ID was not recorded at the time. File SHA-256: [paste hash]. The first ten names are google.com, cloudflare.com, amazonaws.com, facebook.com, ezviz7.com, gstatic.com, fbcdn.net, googleapis.com, akamai.net, microsoft.com.
(format: `rank,domain`). Tranco list ID: [fill in].

## Running

`pytest.ini` sets the Python path for tests only, so set it yourself for everything else (once per terminal):

```bat
set PYTHONPATH=src
python -m pytest -q
```

Scan 100 names with TLS 1.2 and 1.3 (asks you to type YES before sending traffic):

```bat
python -m tlsaudit.runner --domains data/raw/top-1m.csv --skip 0 --limit 100 --timeout 3 --tls12 --network ResWiFi --label top300-part1
```

| Option | Meaning |
|---|---|
| `--skip` / `--limit` | scan a chunk of the list |
| `--timeout` | connect timeout in seconds (1 to 10) |
| `--tls12` | also enumerate TLS 1.2 cipher suites (up to 158 attempts per host) |
| `--network` | label stored in `run.json` |
| `--exclude` | exclusion file (default `data/raw/exclude.txt`) |

Each run is saved to `data/results/runs/<timestamp>_<label>/` and never overwritten.

```bat
python -m tlsaudit.summarize
python -m tlsaudit.analyze data\results\runs\FOLDER_A data\results\runs\FOLDER_B
python -m tlsaudit.compare
```

`analyze` takes one or more run folders (with no arguments it uses the latest). Replace the folder names with your own. `compare` asks for YES before sending traffic.

## Using a new dataset

Save the file in `data\raw\`. `load_domains` accepts .txt or .csv with any column layout, skips headers, URLs, and IP addresses, and counts what it rejects.

```bat
python -c "from tlsaudit.dataset import load_domains; d,r=load_domains(r'data/raw/FILE.csv'); print(len(d), 'valid,', r, 'rejected'); print(d[:5])"
```

Confirm the sample looks right and get approval before scanning, then start with `--limit 10`. Use `--skip` and `--limit` to scan large files in chunks. Exclusions are applied before chunking, so don't change `exclude.txt` between chunks.

## Library comparison (summary)

| Library | Lists all accepted ciphers | What it adds |
|---|---|---|
| SSLyze | **Yes** (one connection per cipher) | Accepted ciphers and certificate detail |
| ssl (Python) | No (negotiated cipher only) | Fast, built-in baseline |
| check-tls | No (negotiated cipher only) | CAA records, certificate fields |
| curl_cffi | No | HTTP status and headers with a browser fingerprint |

On 10 domains (best case, single run), per-host time was 0.18 s (SSLyze, TLS 1.3 only), 0.047 s (ssl), 0.035 s (curl_cffi), and 0.239 s (check-tls). nassl was excluded because it is SSLyze's own engine. See `docs/LIBRARY_COMPARISON.md`.

## Limitations

- A top-300 popularity sample is not representative of all internet services, and hosts share operators.
- TLS 1.2 and 1.3 only. Older protocols were not tested.
- "Accepts" is not "prefers." The legacy-suite flags come from suite names only and are not a vulnerability audit.
- 83 names failed DNS on the campus resolver, and the 13 connection errors have no recorded reason. 23 hosts accepted no TLS 1.3 suite, and the cause is unconfirmed.
- One record (jsdelivr.net) carries a certificate generated by a local antivirus (Norton) and is not a valid server measurement.
- Run time varied up to 6x between identical TLS 1.3 runs (cause unknown). The 100k-host estimates are rough.
- DNS lookups are serial and there is no resume support, so 100k-host runs would need both fixes.
- The library comparison used one run on 10 domains.

## AI assistance
The project plan, debugging, and guidance were assisted with an AI assistant. I ran and tested everything, and `docs/ERROR_LOG.md` records where AI-generated guidance was wrong.

## Docs

- `docs/ERROR_LOG.md`: error log, approval record, and scan log
- `docs/RESULTS.md`: first measurement results
- `docs/TIMING_LOG.md`: timeout tests and run times
- `docs/LIBRARY_COMPARISON.md`: written library comparison