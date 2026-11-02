import pytest
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace as NS

from tlsaudit.scanner import record_from_result, validity_days

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