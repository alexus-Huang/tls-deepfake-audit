import json
import pytest
from tlsaudit.summarize import load_run_records, summary_table

def _rec(**over):
    r = {"run_folder": "r1", "network": "ResWiFi", "domains_scanned": 10,
         "timeout_seconds": 3, "tls12_enabled": False, "duration_seconds": 5.0,
         "status_counts": {"COMPLETED": 8, "DNS_FAILED": 2},
         "tls13_status_counts": {"COMPLETED": 8, "NONE": 2},
         "tls12_status_counts": {"NONE": 10}}
    r.update(over)
    return r

def test_summary_table_math():
    row = summary_table([_rec()]).iloc[0]
    assert row["sec_per_host"] == 0.5
    assert row["hours_per_100k"] == pytest.approx(13.9, abs=0.05)
    assert (row["completed"], row["dns_failed"], row["other_failed"]) == (8, 2, 0)

def test_load_run_records_reads_run_json(tmp_path):
    d = tmp_path / "20261103-100000_x"
    d.mkdir()
    (d / "run.json").write_text(json.dumps({"label": "x"}))
    recs = load_run_records(tmp_path)
    assert recs[0]["label"] == "x" and recs[0]["run_folder"] == "20261103-100000_x"