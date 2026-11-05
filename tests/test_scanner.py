import pytest
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace as NS
from tlsaudit.scanner import record_from_result, validity_days
import json
import tlsaudit.scanner as scanner_module
from sslyze.errors import ServerHostnameCouldNotBeResolved
from tlsaudit.scanner import empty_record, scan_domains

def test_empty_record_has_no_measurements():
    rec = empty_record("x.com", "DNS_FAILED", "NOT_STARTED")
    assert rec["connectivity_status"] == "DNS_FAILED"
    assert rec["issuer"] is None and rec["validity_days"] is None

def test_unresolvable_domain_recorded_not_crash(tmp_path, monkeypatch):
    def cannot_resolve(hostname, port):
        raise ServerHostnameCouldNotBeResolved("fake")

    monkeypatch.setattr(scanner_module, "ServerNetworkLocation", cannot_resolve)
    out = tmp_path / "out.jsonl"
    scan_domains(["nope.example"], out)
    rec = json.loads(out.read_text().splitlines()[0])
    assert rec["domain"] == "nope.example"
    assert rec["connectivity_status"] == "DNS_FAILED"

def test_validity_days_90():
    assert validity_days("2026-09-26T00:00:00+00:00", "2026-12-25T00:00:00+00:00") == 90

def _fake(scan_result):
    return NS(
        server_location=NS(hostname="example.com"),
        connectivity_status=NS(name="COMPLETED"),
        scan_status=NS(name="COMPLETED"),
        scan_result=scan_result,
    )

def test_unreachable_host_recorded_as_data():
    rec = record_from_result(_fake(None))
    assert rec["domain"] == "example.com"
    assert rec["issuer"] is None and rec["tls13_accepted_ciphers"] is None

def test_successful_scan_fields():
    start = datetime(2026, 9, 26, tzinfo=timezone.utc)
    leaf = NS(
        issuer=NS(rfc4514_string=lambda: "CN=Test CA"),
        not_valid_before_utc=start,
        not_valid_after_utc=start + timedelta(days=90),
    )
    sr = NS(
        tls_1_3_cipher_suites=NS(result=NS(accepted_cipher_suites=[
            NS(cipher_suite=NS(name="TLS_AES_128_GCM_SHA256"))])),
        certificate_info=NS(result=NS(certificate_deployments=[
            NS(received_certificate_chain=[leaf])])),
    )
    rec = record_from_result(_fake(sr))
    assert rec["tls13_accepted_ciphers"] == ["TLS_AES_128_GCM_SHA256"]
    assert rec["issuer"] == "CN=Test CA"
    assert rec["validity_days"] == 90