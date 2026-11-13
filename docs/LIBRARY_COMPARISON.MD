# Library comparison: fetching TLS cipher suites

## Purpose and scope

The assignment asked for Python libraries that fetch TLS cipher suites from web servers, with attention to run time at 100,000+ hosts. I compared four tools on the same 10 domains: SSLyze, Python's built-in `ssl` module, check-tls, and curl_cffi. nassl was considered and excluded (see below).

- **Domains:** example.com plus the top 9 Tranco names (google.com, cloudflare.com, amazonaws.com, facebook.com, ezviz7.com, gstatic.com, fbcdn.net, googleapis.com, akamai.net).
- **Run:** 2026-11-02, about 8:28 PM PST, from campus ResWiFi. One run per library, one library at a time.
- **SSLyze scope in this comparison:** certificate plus TLS 1.3 cipher suites only. TLS 1.2 was added later for the 300-domain run.

## Summary

| Question | SSLyze | ssl (stdlib) | check-tls | curl_cffi |
|---|---|---|---|---|
| Lists all accepted cipher suites? | **Yes** | No | No | No |
| Negotiated cipher and TLS version | Through its accepted-suite list | Yes | Yes | No (exposes no cipher or version) |
| Certificate details | Issuer, validity dates (extracted by my scanner) | Issuer (extracted by my probe) | Issuer, validity, key type and size, SANs, SCT presence | None (only a verify-result code) |
| CAA records | No | No | Yes | No |
| HTTP response | No | No | HSTS probe (disabled in my runs) | Yes (HEAD: status and headers) |
| Requests per host in my runs | 5 TLS 1.3 cipher attempts + certificate check | 1 handshake | 1 connection + CAA DNS lookup | 1 HEAD request |
| Time per host (10 domains, 1 run) | 0.180 s | 0.047 s | 0.239 s | 0.035 s |
| Best-case time for 100k hosts | 5.0 h | 1.3 h | 6.6 h | 1.0 h |
| License | AGPL | PSF | MIT | MIT |

## The libraries

**SSLyze (6.3.1).** It tests every cipher suite as its own connection. I confirmed this in its code and by counting its cipher lists: TLS 1.3 has 5, TLS 1.2 has 158, TLS 1.0, TLS 1.1, and SSL 3.0 have 121 each, SSL 2.0 has 7. It is the only tool here that reports which suites a server accepts, so it is the one that answers the research question. It has built-in concurrency limits, which I set from my safety config. Its retry setting is really total attempts, and only timeouts are retried.

**ssl (Python 3.12.2, OpenSSL 3.0.13).** One handshake gives the negotiated version and cipher, so it shows what the server chose, not what it accepts. Python's default context also refuses TLS 1.0 and 1.1 (minimum TLS 1.2) and rejects invalid certificates, so those hosts return an error and no data. I did not test whether restricting the cipher list could enumerate TLS 1.2 suites, and I would expect the local OpenSSL to refuse some weak suites.

**check-tls (1.10.0).** A certificate analyzer with a command line. It returned certificate fields, CAA records, and a connection summary with `tls_version`, `cipher_suite`, `supports_tls13`, and `alpn_protocol`, so it reports one negotiated cipher, not a list. It is a one-maintainer project with no build provenance, so I installed it in its own virtual environment. Its README listed three optional checks (crt.sh, CRL, OCSP) but its `--help` also showed an HSTS probe that sends an HTTP request to the site. I ran it with `-m simple` and all four disabled, and every disabled check shows `"checked": false` in the output.

**curl_cffi (0.17.0).** An HTTP client that impersonates a browser's TLS and HTTP/2 fingerprint. It is not a scanner. Its `CurlInfo` fields include only verify-result and session-pointer entries, so it exposes no negotiated cipher or version. I used it to compare how a server answers a browser-style client: one HEAD request, no redirects, no retries, no body download, on benign domains only. Its documentation promotes bypassing bot protection, so I limited it to one polite request.

**nassl (excluded).** SSLyze's own OpenSSL wrapper. Comparing it with SSLyze would compare SSLyze with its own engine, it is low-level (I would have to write the scanner), and its README describes it as experimental.

## What they returned on the 10 domains

- **Reachability:** 8 of 10 completed in every library. `ezviz7.com` and `akamai.net` failed DNS in all four, so the failure belongs to the names, not a tool.
- **Cipher suites:** for all 8 reachable hosts, SSLyze found the same 3 of the 5 TLS 1.3 suites accepted (ChaCha20-Poly1305, AES-256-GCM, AES-128-GCM). `ssl` and check-tls each reported one cipher per host and agreed on all 8: AES-256-GCM for 5 hosts, AES-128-GCM for amazonaws.com, and ChaCha20-Poly1305 for facebook.com and fbcdn.net. So the same host looked different depending on the tool: three accepted suites from SSLyze, one chosen suite from the others.
- **Certificates:** validity ranged from 83 to 197 days across the 8 hosts. All three tools that read certificates agreed on issuers.
- **CAA (check-tls):** 6 of 8 hosts publish CAA records. Google's domains list pki.goog only, Facebook's list DigiCert only, and cloudflare.com lists five issuers (comodoca.com, digicert.com, letsencrypt.org, pki.goog, ssl.com). example.com and amazonaws.com have none. Values print as Python bytes text (`b'issue'`) and needed cleaning.
- **HTTP (curl_cffi):** statuses were 200 (1 host), 301 (5), 302 (1), and 404 (googleapis.com). HSTS appeared on the first response for 3 hosts (cloudflare.com, facebook.com, fbcdn.net). I followed no redirects, so a host that sends HSTS only on a later response would count as no. I saw no sign that a server treated the browser-style client differently from the others.

## Speed

Method: time one library over the 10 domains, divide by 10 for seconds per host, then multiply by 100,000 and divide by 3,600 for hours.

| Library | Seconds (10 domains) | Sec/host | 100k hosts (hours) |
|---|---|---|---|
| curl_cffi | 0.35 | 0.035 | 1.0 |
| ssl | 0.47 | 0.047 | 1.3 |
| SSLyze | 1.80 | 0.180 | 5.0 |
| check-tls | 2.39 | 0.239 | 6.6 |

These are best-case estimates and the comparison is not like-for-like:
- One run on 10 hosts, 8 of them large and fast. The two DNS failures finished almost instantly.
- check-tls starts a new process for each group of 5 domains, so its time includes start-up.
- SSLyze does 6 attempts per host here and 164 with TLS 1.2.
- The estimate assumes a straight line to 100k hosts and includes no slow or dead hosts.

Later SSLyze runs give a wider picture: 100 domains with TLS 1.3 took 0.11 to 0.63 s per host across six runs with identical outcomes, and 300 domains with TLS 1.2 and 1.3 took 1.56 s per host, about 43 hours per 100k at that mix. The other three libraries were not run at that scale, so their numbers rest on the 10-domain run alone.

## Safety differences

- **SSLyze:** the most traffic per host, controlled by my limits (5 hosts, 2 connections per host, 1 attempt). Vulnerability probes are blocked by an allowlist.
- **ssl:** one handshake per host.
- **curl_cffi:** one HEAD request per host, with retries and redirects off.
- **check-tls:** safe only after disabling its checks that contact third parties (crt.sh, CAs, the site's HTTP port). Disabling them is covered by a test.

## Notes

- **SSLyze** It is the only tool that lists accepted suites, and TLS 1.2 is where hosts differ most, so a negotiated-cipher tool would hide the differences.
- **check-tls** adds CAA records and richer certificate fields, if those matter.
- **ssl** is a good lightweight liveness and negotiated-cipher check.
- **curl_cffi** answers a different question: how a server responds to a browser-style client.
- **At 100k hosts:** SSLyze is slower per host, but run time depends more on dead and unresponsive hosts than on working ones (see my timeout tests), and DNS lookups need to be parallel. An untested idea is to use a one-handshake probe first to skip dead hosts, then run the SSLyze enumeration on the rest.

## Limitations

- One run, 10 domains, mostly large sites. No variation between runs was measured.
- Timings are best-case and not like-for-like.
- check-tls's `connection_health` fields beyond those listed were not examined.
- I did not test whether `ssl` could enumerate TLS 1.2 suites.
- Library maturity and maintenance were judged from PyPI and GitHub pages only, not from reading the source.
- The comparison used TLS 1.3 only. TLS 1.2 results exist for SSLyze only.

## Reproduce

```bat
set PYTHONPATH=src
python -m tlsaudit.compare
```

This needs `.venv-checktls` with check-tls installed, and asks for YES before sending traffic.