from collections import Counter
from tlsaudit.analyze import overview, suite_flags, suite_table, version_summary

def test_suite_flags():
    assert suite_flags("TLS_AES_128_GCM_SHA256") == []
    assert suite_flags("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == []
    assert suite_flags("TLS_RSA_WITH_AES_128_GCM_SHA256") == ["no_forward_secrecy"]
    assert suite_flags("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA") == ["legacy_by_name"]
    assert suite_flags("TLS_RSA_WITH_3DES_EDE_CBC_SHA") == ["no_forward_secrecy", "legacy_by_name"]

def test_version_summary_counts_hosts_not_suites():
    recs = [{"x": ["A", "B"]}, {"x": ["A"]}, {"x": []}, {"x": None}, {}]
    s = version_summary(recs, "x")
    assert s["hosts_scanned"] == 3 and s["hosts_supporting"] == 2
    assert s["suite_counts"] == Counter({"A": 2, "B": 1})

def test_suite_table_percent_of_supporting_hosts():
    s = {"hosts_scanned": 3, "hosts_supporting": 2, "suite_counts": Counter({"A": 2, "B": 1})}
    t = suite_table(s)
    assert list(t["suite"]) == ["A", "B"]
    assert list(t["percent_of_supporting"]) == [100.0, 50.0]

def test_overview():
    recs = [{"connectivity_status": "COMPLETED", "validity_days": 90, "issuer": "CN=X"},
            {"connectivity_status": "DNS_FAILED"}]
    o = overview(recs)
    assert o["domains"] == 2 and o["status"] == {"COMPLETED": 1, "DNS_FAILED": 1}
    assert o["validity_days"] == (90, 90, 90) and o["top_issuers"] == [("CN=X", 1)]