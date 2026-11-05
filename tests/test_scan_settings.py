import pytest
from sslyze import ScanCommand
from tlsaudit.config import ScanConfig
from tlsaudit.scan_settings import (
    ALLOWED_SCAN_COMMANDS, DEFAULT_SCAN_COMMANDS, build_network_config,
    scan_commands, scanner_kwargs,
)

def test_scanner_kwargs_use_agreed_limits():
    assert scanner_kwargs(ScanConfig()) == {
        "per_server_concurrent_connections_limit": 2,
        "concurrent_server_scans_limit": 5,
    }

def test_scanner_kwargs_follow_a_lower_config():
    kw = scanner_kwargs(ScanConfig(parallel_hosts=1, connections_per_host=1))
    assert kw["concurrent_server_scans_limit"] == 1
    assert kw["per_server_concurrent_connections_limit"] == 1

def test_network_config_timeout_and_single_attempt():
    nc = build_network_config("example.com", ScanConfig(connect_timeout=3))
    assert nc.network_timeout == 3
    assert nc.network_max_retries == 1  # 0 retries = 1 attempt

@pytest.mark.parametrize("bad", ["http://example.com", "192.168.1.1", "example.com/path", "Example.com"])
def test_network_config_rejects_non_hostnames(bad):
    with pytest.raises(ValueError):
        build_network_config(bad, ScanConfig())

def test_allowlist_only_certificate_and_cipher_suite_scans():
    for cmd in ALLOWED_SCAN_COMMANDS:
        assert cmd == ScanCommand.CERTIFICATE_INFO or cmd.name.endswith("_CIPHER_SUITES")

@pytest.mark.parametrize("name", ["HEARTBLEED", "OPENSSL_CCS_INJECTION", "ROBOT", "SESSION_RENEGOTIATION"])
def test_vulnerability_probes_not_allowed(name):
    assert ScanCommand[name] not in ALLOWED_SCAN_COMMANDS

def test_default_scan_is_tls13_and_cert_only():
    assert scan_commands() == {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    }

def test_tls12_requires_explicit_opt_in():
    assert ScanCommand.TLS_1_2_CIPHER_SUITES not in scan_commands()
    assert ScanCommand.TLS_1_2_CIPHER_SUITES in scan_commands(include_tls12=True)

@pytest.mark.parametrize("name", ["SSL_2_0_CIPHER_SUITES", "SSL_3_0_CIPHER_SUITES",
                                  "TLS_1_0_CIPHER_SUITES", "TLS_1_1_CIPHER_SUITES"])
def test_deprecated_protocol_cipher_scans_never_allowed(name):
    assert ScanCommand[name] not in scan_commands(include_tls12=True)