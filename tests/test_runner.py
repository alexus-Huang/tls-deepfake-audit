import json
from datetime import datetime
import pytest
import tlsaudit.runner as runner

def _domains_file(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("a.com\nb.com\nbad url\n")
    return f

def test_cancelled_run_sends_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr("builtins.input", lambda _: "no")

    def boom(*a, **k):
        raise AssertionError("scan must not run")
    monkeypatch.setattr(runner, "scan_domains", boom)
    code = runner.main(["--domains", str(_domains_file(tmp_path)), "--network", "test"])
    assert code == 0 and not (tmp_path / "runs").exists()

def test_timeout_above_ceiling_rejected(tmp_path):
    with pytest.raises(SystemExit):
        runner.main(["--domains", str(_domains_file(tmp_path)), "--network", "test", "--timeout", "60"])

def test_run_saves_record(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "RUNS_DIR", tmp_path / "runs")
    seen = {}

    def fake_scan(domains, out_path, cfg, include_tls12=False):
        seen.update(domains=domains, timeout=cfg.connect_timeout, tls12=include_tls12)
        with open(out_path, "w") as f:
            for d in domains:
                f.write(json.dumps({"domain": d, "connectivity_status": "COMPLETED"}) + "\n")
    monkeypatch.setattr(runner, "scan_domains", fake_scan)

    code = runner.main(["--domains", str(_domains_file(tmp_path)), "--network", "ResWiFi",
                        "--timeout", "3", "--tls12", "--label", "t", "--yes"])
    assert code == 0
    run_dir = next((tmp_path / "runs").iterdir())
    info = json.loads((run_dir / "run.json").read_text())
    assert seen == {"domains": ["a.com", "b.com"], "timeout": 3, "tls12": True}
    assert info["network"] == "ResWiFi" and info["domains_scanned"] == 2
    assert info["status_counts"] == {"COMPLETED": 2}
    assert info["rejected_lines"] == 1


def test_count_field(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text('{"a": "X"}\n{"a": "X"}\n{"a": null}\n{}\n')
    assert runner.count_field(f, "a") == {"X": 2, "NONE": 2}

def test_run_folder_name_is_filesystem_safe():
    assert runner.run_folder_name("tls12 / 3s!", datetime(2026, 11, 3, 10, 5, 9)) == "20261103-100509_tls12---3s-"

def test_runner_applies_exclusions(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "RUNS_DIR", tmp_path / "runs")
    ex = tmp_path / "ex.txt"
    ex.write_text("b.com\n")
    seen = {}

    def fake_scan(domains, out_path, cfg, include_tls12=False):
        seen["domains"] = domains
        open(out_path, "w").close()
    monkeypatch.setattr(runner, "scan_domains", fake_scan)

    code = runner.main(["--domains", str(_domains_file(tmp_path)), "--network", "t",
                        "--exclude", str(ex), "--yes"])
    assert code == 0 and seen["domains"] == ["a.com"]
    info = json.loads((next((tmp_path / "runs").iterdir()) / "run.json").read_text())
    assert info["excluded_domains"] == ["b.com"]