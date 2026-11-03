"""Comparison harness: same domains, same safety limits, one library at a time.

Libraries compared: SSLyze (via our scanner), Python's ssl module,
curl_cffi, and check-tls. Sends real traffic: benign, approved domains only.
"""
import json
import socket
import ssl
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from curl_cffi import requests as curl_requests

from .config import ScanConfig
from .dataset import load_tranco, normalize_domain
from .scanner import scan_domains

CHECK_TLS_EXE = Path(".venv-checktls/Scripts/check-tls.exe")
# Skip everything that contacts third parties (crt.sh, CAs, the site's HTTP port).
CHECK_TLS_FLAGS = ["-m", "simple", "--no-transparency", "--no-crl-check",
                   "--no-ocsp-check", "--no-hsts-check"]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _require_hostname(domain):
    if normalize_domain(domain) != domain:
        raise ValueError(f"not a plain lowercase hostname: {domain!r}")


def classify_error(exc):
    """Map an exception to a short status label. Failures are data, never retried."""
    if isinstance(exc, socket.gaierror):
        return "DNS_FAILED"
    if isinstance(exc, TimeoutError):
        return "TIMEOUT"
    if isinstance(exc, ConnectionError):
        return "CONNECTION_REFUSED_OR_RESET"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "CERT_INVALID"
    if isinstance(exc, ssl.SSLError):
        return "TLS_ERROR"
    return "OTHER_ERROR"


# ---------- Library: Python ssl (1 TCP connection + 1 handshake per host) ----------
def probe_ssl(domain, cfg):
    _require_hostname(domain)
    rec = {"library": "ssl", "domain": domain, "scanned_at": _now(),
           "status": "COMPLETED", "tls_version": None, "cipher": None, "issuer": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=cfg.connect_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                rec["tls_version"] = tls.version()
                rec["cipher"] = tls.cipher()[0]
                cert = tls.getpeercert()
                issuer = dict(item[0] for item in cert.get("issuer", ()))
                rec["issuer"] = issuer.get("commonName")
    except Exception as exc:
        rec["status"] = classify_error(exc)
    return rec


def probe_ssl_all(domains, cfg):
    with ThreadPoolExecutor(max_workers=cfg.parallel_hosts) as pool:
        return list(pool.map(lambda d: probe_ssl(d, cfg), domains))


# ---------- Library: curl_cffi (1 HEAD request per host, no retries) ----------
def probe_curl(domain, cfg):
    _require_hostname(domain)
    rec = {"library": "curl_cffi", "domain": domain, "scanned_at": _now(),
           "status": "COMPLETED", "http_status": None, "server": None, "hsts": None}
    try:
        r = curl_requests.head(f"https://{domain}/", impersonate="chrome",
                               timeout=cfg.connect_timeout, allow_redirects=False)
        headers = {k.lower(): v for k, v in r.headers.items()}
        rec["http_status"] = r.status_code
        rec["server"] = headers.get("server")
        rec["hsts"] = "strict-transport-security" in headers
    except Exception as exc:
        rec["status"] = "ERROR_" + type(exc).__name__
    return rec


def probe_curl_all(domains, cfg):
    with ThreadPoolExecutor(max_workers=cfg.parallel_hosts) as pool:
        return list(pool.map(lambda d: probe_curl(d, cfg), domains))


# ---------- Library: check-tls (separate venv, run as a command) ----------
def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def check_tls_command(exe, domains, json_path):
    return [str(exe), *domains, *CHECK_TLS_FLAGS, "-j", str(json_path)]


def probe_check_tls(domains, cfg, exe=CHECK_TLS_EXE):
    for d in domains:
        _require_hostname(d)
    records = []
    for group in chunks(list(domains), cfg.parallel_hosts):
        data, error = [], None
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            try:
                subprocess.run(check_tls_command(exe, group, out),
                               capture_output=True, text=True, timeout=60)
                data = json.loads(out.read_text(encoding="utf-8"))
            except Exception as exc:
                error = "ERROR_" + type(exc).__name__
        by_domain = {str(item.get("domain", "")).split(":")[0]: item for item in data}
        for d in group:
            item = by_domain.get(d)
            records.append({
                "library": "check_tls", "domain": d, "scanned_at": _now(),
                "status": item.get("status") if item else (error or "NO_OUTPUT"),
                "caa_check": item.get("caa_check") if item else None,
                "raw": item,   # keep everything so we can inspect the real fields
            })
    return records


# ---------- Orchestration and timing ----------
def extrapolate_hours(seconds, n_hosts, target=100_000):
    """Best-case hours for `target` hosts, from a small measured run."""
    if n_hosts <= 0:
        raise ValueError("n_hosts must be positive")
    return seconds / n_hosts * target / 3600


def _write_jsonl(path, records):
    with Path(path).open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def run_comparison(domains, out_dir, cfg=None):
    cfg = cfg or ScanConfig()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("compare_*.jsonl"):   # scan_domains appends; start clean
        old.unlink()

    timing = {}

    t = time.time()
    scan_domains(domains, out_dir / "compare_sslyze.jsonl", cfg)
    timing["sslyze"] = time.time() - t

    for name, fn in (("ssl", probe_ssl_all), ("curl_cffi", probe_curl_all),
                     ("check_tls", probe_check_tls)):
        t = time.time()
        records = fn(domains, cfg)
        timing[name] = time.time() - t
        _write_jsonl(out_dir / f"compare_{name}.jsonl", records)

    n = len(domains)
    print(f"{'library':<10} {'seconds':>8} {'sec/host':>9} {'100k hosts (hours, best case)':>30}")
    for name, secs in timing.items():
        print(f"{name:<10} {secs:>8.2f} {secs / n:>9.3f} {extrapolate_hours(secs, n):>30.1f}")
    (out_dir / "compare_timing.json").write_text(
        json.dumps({"n_hosts": n, "seconds": timing}, indent=2), encoding="utf-8")
    return timing


def main():
    domains = ["example.com"] + load_tranco("data/raw/top-1m.csv", 9)
    print("Domains:", domains)
    print("Limits: 5 hosts at once, 2 connections per host, 5 s timeout, no retries.")
    if input("Type YES to send traffic to these domains: ").strip() != "YES":
        print("Cancelled. Nothing was sent.")
        return
    run_comparison(domains, "data/results")


if __name__ == "__main__":
    main()