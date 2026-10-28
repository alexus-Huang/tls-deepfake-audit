import pytest
from tlsaudit.dataset import (
    normalize_domain, read_domain_file, load_tranco, build_dataset,
)


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("evil-site[.]com", "evil-site.com"),
    ("example.com.", "example.com"),
    ("  a.b.org  ", "a.b.org"),
    ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
])
def test_normalize_valid(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "# comment", "http://example.com", "example.com/path",
    "example.com:8080", "192.168.1.1", "localhost", "-bad.com", None,
])
def test_normalize_rejects_junk(raw):
    assert normalize_domain(raw) is None


def test_read_domain_file_dedupes_and_skips_comments(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# hi\na.com\nA.com\nb[.]net\nhttp://x.com\n")
    assert read_domain_file(f) == ["a.com", "b.net"]


def test_read_domain_file_missing_returns_empty(tmp_path):
    assert read_domain_file(tmp_path / "nope.txt") == []


def test_load_tranco_respects_limit(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text("1,google.com\n2,facebook.com\n3,example.org\n")
    assert load_tranco(f, limit=2) == ["google.com", "facebook.com"]


def test_build_dataset_groups_and_overlap(tmp_path):
    tr = tmp_path / "tr.csv"
    tr.write_text("1,good.com\n2,both.com\n")
    th = tmp_path / "th.txt"
    th.write_text("bad.net\nboth.com\n")
    df = build_dataset(tr, {"phishing_lure": th})
    assert set(df["domain"]) == {"good.com", "bad.net"}   # overlap dropped
    assert df.set_index("domain").loc["bad.net", "group"] == "phishing_lure"