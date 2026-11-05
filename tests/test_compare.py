import json
import socket
import ssl
from pathlib import Path
import pytest
import tlsaudit.compare as cmp
from tlsaudit.config import ScanConfig


def test_classify_errors():
    assert cmp.classify_error(socket.gaierror()) == "DNS_FAILED"
    assert cmp.classify_error(TimeoutError()) == "TIMEOUT"
    assert cmp.classify_error(ConnectionResetError()) == "CONNECTION_REFUSED_OR_RESET"
    assert cmp.classify_error(ssl.SSLCertVerificationError()) == "CERT_INVALID"
    assert cmp.classify_error(ssl.SSLError()) == "TLS_ERROR"
    assert cmp.classify_error(ValueError()) == "OTHER_ERROR"

def test_probe_ssl_failure_recorded(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror()
    monkeypatch.setattr(cmp.socket, "create_connection", boom)
    rec = cmp.probe_ssl("nope.example", ScanConfig())
    assert rec["status"] == "DNS_FAILED" and rec["cipher"] is None

@pytest.mark.parametrize("fn", [cmp.probe_ssl, cmp.probe_curl])
def test_non_hostname_rejected(fn):
    with pytest.raises(ValueError):
        fn("http://example.com", ScanConfig())

def test_probe_curl_records_headers(monkeypatch):
    class R:
        status_code = 200
        headers = {"Server": "x", "Strict-Transport-Security": "max-age=1"}
    monkeypatch.setattr(cmp.curl_requests, "head", lambda *a, **k: R())
    rec = cmp.probe_curl("example.com", ScanConfig())
    assert rec["http_status"] == 200 and rec["hsts"] is True and rec["server"] == "x"


def test_curl_request_is_single_polite_head(monkeypatch):
    seen = {}

    def fake_head(url, **kw):
        seen.update(kw)
        raise RuntimeError("stop")
    monkeypatch.setattr(cmp.curl_requests, "head", fake_head)
    rec = cmp.probe_curl("example.com", ScanConfig(connect_timeout=3))
    assert seen["allow_redirects"] is False and seen["timeout"] == 3
    assert "retry" not in seen
    assert rec["status"] == "ERROR_RuntimeError"


def test_check_tls_command_has_all_safety_flags(tmp_path):
    cmd = cmp.check_tls_command("x.exe", ["a.com"], tmp_path / "o.json")
    for flag in ["--no-transparency", "--no-crl-check", "--no-ocsp-check", "--no-hsts-check"]:
        assert flag in cmd
    assert cmd[cmd.index("-m") + 1] == "simple"

def test_chunks_never_exceed_parallel_limit():
    assert [len(c) for c in cmp.chunks(list("abcdefghijk"), 5)] == [5, 5, 1]

def test_extrapolate_hours():
    assert cmp.extrapolate_hours(1.5, 10) == pytest.approx(1.5 / 10 * 100000 / 3600)

def test_probe_check_tls_parses_and_matches_domains(monkeypatch):
    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-j") + 1]
        Path(out).write_text(json.dumps(
            [{"domain": "example.com:443", "status": "completed", "caa_check": {"x": 1}}]))
    monkeypatch.setattr(cmp.subprocess, "run", fake_run)
    by = {r["domain"]: r for r in cmp.probe_check_tls(["example.com", "other.com"], ScanConfig())}
    assert by["example.com"]["status"] == "completed"
    assert by["other.com"]["status"] == "NO_OUTPUT"