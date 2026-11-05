"""Turn our ScanConfig safety limits into SSLyze settings. Sends no traffic."""
from sslyze import ScanCommand, ServerNetworkConfiguration
from .config import ScanConfig
from .dataset import normalize_domain

# Tier 1 (default): certificate info + TLS 1.3 (5 ciphers).
DEFAULT_SCAN_COMMANDS = frozenset({
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
})
# Tier 2 (opt-in only): TLS 1.2 adds up to 158 attempts per host.
TLS12_OPT_IN = frozenset({ScanCommand.TLS_1_2_CIPHER_SUITES})

ALLOWED_SCAN_COMMANDS = DEFAULT_SCAN_COMMANDS | TLS12_OPT_IN


def scan_commands(include_tls12: bool = False) -> frozenset:
    """Which scan commands to run. TLS 1.2 only when explicitly requested."""
    return ALLOWED_SCAN_COMMANDS if include_tls12 else DEFAULT_SCAN_COMMANDS

def scanner_kwargs(cfg: ScanConfig) -> dict:
    """Settings for sslyze.Scanner(**kwargs)."""
    return {
        "per_server_concurrent_connections_limit": cfg.connections_per_host,
        "concurrent_server_scans_limit": cfg.parallel_hosts,
    }

def build_network_config(hostname: str, cfg: ScanConfig) -> ServerNetworkConfiguration:
    """Per-host network settings. Refuses anything that isn't a plain hostname."""
    if normalize_domain(hostname) != hostname:
        raise ValueError(f"not a plain lowercase hostname: {hostname!r}")
    return ServerNetworkConfiguration(
        tls_server_name_indication=hostname,
        network_timeout=cfg.connect_timeout,
        # Because of how SSLyze interprets this setting, it represents total attempts, so 0 retries means 1 attempt.
        network_max_retries=cfg.max_retries + 1,
    )