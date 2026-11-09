import pytest
from tlsaudit.dataset import load_exclusions
from tlsaudit.dataset import is_excluded
from tlsaudit.dataset import (
    normalize_domain, read_domain_file, load_tranco, build_dataset,
)
from tlsaudit.dataset import load_domains
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

def test_load_domains_csv_with_header_and_junk(tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("rank,domain\n1,google.com\n2,Example.ORG\n# c\n3,bad url\n4,google.com\n5,http://x.com\n")
    domains, rejected = load_domains(f)
    assert domains == ["google.com", "example.org"]
    assert rejected == 3  # header, 'bad url', and the URL

def test_load_domains_skip_and_limit(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("a.com\nb.com\nc.com\nd.com\n")
    assert load_domains(f, limit=2, skip=1)[0] == ["b.com", "c.com"]

def test_exclusions_exact_and_suffix(tmp_path):
    f = tmp_path / "ex.txt"
    f.write_text("# comment\nwww.gov.uk\n.mil\nBlocked[.]com\n")
    exact, suffixes = load_exclusions(f)
    assert is_excluded("www.gov.uk", exact, suffixes)
    assert not is_excluded("gov.uk", exact, suffixes)
    assert is_excluded("army.mil", exact, suffixes) and is_excluded("mil", exact, suffixes)
    assert is_excluded("blocked.com", exact, suffixes)
    assert not is_excluded("notmil.com", exact, suffixes)
    assert not is_excluded("google.com", exact, suffixes)

def test_missing_exclusion_file_means_no_exclusions(tmp_path):
    assert load_exclusions(tmp_path / "nope.txt") == (set(), set())

def test_load_domains_skips_excluded_before_limit(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("a.com\nwww.gov.uk\nb.com\nc.com\n")
    gone = []
    d, r = load_domains(f, limit=3, exclude=({"www.gov.uk"}, set()), excluded=gone)
    assert d == ["a.com", "b.com", "c.com"]
    assert gone == ["www.gov.uk"]