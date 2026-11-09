"""Tier 1 scanner: certificate info + TLS 1.3 ciphers. Writes JSON Lines."""
import json
from datetime import datetime, timezone
from pathlib import Path
from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
from sslyze.errors import ServerHostnameCouldNotBeResolved
from .config import ScanConfig
from .scan_settings import build_network_config, scan_commands, scanner_kwargs

def _utc(cert, field):
    """Certificate dates: newer cryptography has *_utc attributes."""
    value = getattr(cert, field + "_utc", None) or getattr(cert, field)
    return value.isoformat()

def validity_days(not_before_iso, not_after_iso):
    """Certificate lifetime in whole days."""
    start = datetime.fromisoformat(not_before_iso)
    end = datetime.fromisoformat(not_after_iso)
    return (end - start).days

def empty_record(domain, connectivity_status, scan_status):
    """A record with every measurement empty. Used for failures."""
    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "connectivity_status": connectivity_status,
        "scan_status": scan_status,
        "tls13_status": None,
        "tls13_accepted_ciphers": None,
        "tls12_status": None,
        "tls12_accepted_ciphers": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "validity_days": None,
    }


def _accepted(attempt):
    """Accepted cipher names from a cipher-suite scan, or None if it has no result."""
    if attempt is None or attempt.result is None:
        return None
    return [c.cipher_suite.name for c in attempt.result.accepted_cipher_suites]

def _status(attempt):
    return getattr(getattr(attempt, "status", None), "name", None)

def record_from_result(result):
    """Turn one SSLyze result into a flat, JSON-friendly dict.
    """
    rec = empty_record(
        result.server_location.hostname,
        result.connectivity_status.name,
        result.scan_status.name,
    )
    if result.scan_result is None:       # host never answered properly
        return rec

    sr = result.scan_result
    t13 = getattr(sr, "tls_1_3_cipher_suites", None)
    t12 = getattr(sr, "tls_1_2_cipher_suites", None)
    rec["tls13_accepted_ciphers"] = _accepted(t13)
    rec["tls13_status"] = _status(t13)
    rec["tls12_accepted_ciphers"] = _accepted(t12)
    rec["tls12_status"] = _status(t12)

    cert_attempt = getattr(sr, "certificate_info", None)
    if (cert_attempt is not None and cert_attempt.result is not None
            and cert_attempt.result.certificate_deployments):
        leaf = cert_attempt.result.certificate_deployments[0].received_certificate_chain[0]
        rec["issuer"] = leaf.issuer.rfc4514_string()
        rec["not_before"] = _utc(leaf, "not_valid_before")
        rec["not_after"] = _utc(leaf, "not_valid_after")
        rec["validity_days"] = validity_days(rec["not_before"], rec["not_after"])
    return rec


def scan_domains(domains, out_path, cfg=None, include_tls12=False):
    """Scan plain hostnames (port 443 only) and append one JSON line each."""
    cfg = cfg or ScanConfig()
    requests, failures = [], []
    for d in domains:
        network_config = build_network_config(d, cfg)
        try:
            location = ServerNetworkLocation(hostname=d, port=443)
        except ServerHostnameCouldNotBeResolved:
            failures.append(empty_record(d, "DNS_FAILED", "NOT_STARTED"))
            continue
        requests.append(ServerScanRequest(
            server_location=location,
            network_configuration=network_config,
            scan_commands=set(scan_commands(include_tls12)),
        ))

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as f:
        for rec in failures:
            f.write(json.dumps(rec) + "\n")
        f.flush()
        if not requests:
            return
        scanner = Scanner(**scanner_kwargs(cfg))
        scanner.queue_scans(requests)
        for result in scanner.get_results():
            f.write(json.dumps(record_from_result(result)) + "\n")
            f.flush()             