"""Safety limits for all scanning.
"""
from dataclasses import dataclass

MAX_PARALLEL_HOSTS = 5
MAX_CONNECTIONS_PER_HOST = 2
MAX_TIMEOUT_SECONDS = 10
MAX_RETRIES = 0


@dataclass(frozen=True)
class ScanConfig:
    parallel_hosts: int = 5
    connections_per_host: int = 2
    connect_timeout: int = 5   # seconds; slow or firewalled hosts are skipped
    max_retries: int = 0       # no hammering hosts that don't answer

    def __post_init__(self):
        if not 1 <= self.parallel_hosts <= MAX_PARALLEL_HOSTS:
            raise ValueError(f"parallel_hosts must be 1..{MAX_PARALLEL_HOSTS}")
        if not 1 <= self.connections_per_host <= MAX_CONNECTIONS_PER_HOST:
            raise ValueError(f"connections_per_host must be 1..{MAX_CONNECTIONS_PER_HOST}")
        if not 1 <= self.connect_timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"connect_timeout must be 1..{MAX_TIMEOUT_SECONDS}")
        if not 0 <= self.max_retries <= MAX_RETRIES:
            raise ValueError(f"max_retries must be 0..{MAX_RETRIES}")