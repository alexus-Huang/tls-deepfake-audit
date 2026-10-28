import pytest
from tlsaudit.config import ScanConfig


def test_defaults_are_within_agreed_limits():
    c = ScanConfig()
    assert (c.parallel_hosts, c.connections_per_host) == (5, 2)
    assert c.max_retries == 0


@pytest.mark.parametrize("kwargs", [
    {"parallel_hosts": 6},
    {"parallel_hosts": 0},
    {"connections_per_host": 3},
    {"connect_timeout": 60},
    {"max_retries": 2},
])
def test_unsafe_values_rejected(kwargs):
    with pytest.raises(ValueError):
        ScanConfig(**kwargs)