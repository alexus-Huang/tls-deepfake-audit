"""Tier 1 scanner: certificate info + TLS 1.3 ciphers. Writes JSON Lines."""
import json
from datetime import datetime, timezone
from pathlib import Path

from sslyze import (Scanner, ServerNetworkLocation, ServerScanRequest)

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


def record_from_result(result):
    """Turn one SSLyze result into a flat, JSON-friendly dict.

    Failures are recorded as data (status field), never retried.
    """
    rec = {
        "domain": result.server_location.hostname,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "connectivity_status": result.connectivity_status.name,
        "scan_status": result.scan_status.name,
        "tls13_accepted_ciphers": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "validity_days": None,
    }
    if result.scan_result is None:       # host never answered
        return rec

    sr = result.scan_result
    tls13 = sr.tls_1_3_cipher_suites
    if tls13.result is not None:
        rec["tls13_accepted_ciphers"] = [
            c.cipher_suite.name for c in tls13.result.accepted_cipher_suites
        ]
    cert_attempt = sr.certificate_info
    if cert_attempt.result is not None and cert_attempt.result.certificate_deployments:
        leaf = cert_attempt.result.certificate_deployments[0].received_certificate_chain[0]
        rec["issuer"] = leaf.issuer.rfc4514_string()
        rec["not_before"] = _utc(leaf, "not_valid_before")
        rec["not_after"] = _utc(leaf, "not_valid_after")
        rec["validity_days"] = validity_days(rec["not_before"], rec["not_after"])
    return rec


def scan_domains(domains, out_path, cfg=None, include_tls12=False):
    """Scan plain hostnames (port 443 only) and append one JSON line each."""
    cfg = cfg or ScanConfig()
    requests = [
        ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=d, port=443),
            network_configuration=build_network_config(d, cfg),
            scan_commands=set(scan_commands(include_tls12)),
        )
        for d in domains          
    ]
    scanner = Scanner(**scanner_kwargs(cfg))
    scanner.queue_scans(requests)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as f:
        for result in scanner.get_results():
            f.write(json.dumps(record_from_result(result)) + "\n")
            f.flush()             