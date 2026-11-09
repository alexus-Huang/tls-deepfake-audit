"""Summarize every saved run into one table, also saved as CSV for Google Sheets."""
import json
from pathlib import Path
import pandas as pd
from .runner import RUNS_DIR

def load_run_records(runs_dir=RUNS_DIR):
    records = []
    for path in sorted(Path(runs_dir).glob("*/run.json")):
        info = json.loads(path.read_text(encoding="utf-8"))
        info["run_folder"] = path.parent.name
        records.append(info)
    return records

def summary_table(records):
    rows = []
    for r in records:
        n = r["domains_scanned"]
        secs = r["duration_seconds"]
        completed = r["status_counts"].get("COMPLETED", 0)
        dns_failed = r["status_counts"].get("DNS_FAILED", 0)
        rows.append({
            "run": r["run_folder"],
            "network": r["network"],
            "domains": n,
            "timeout_s": r["timeout_seconds"],
            "tls12": r["tls12_enabled"],
            "seconds": round(secs, 2),
            "sec_per_host": round(secs / n, 3),
            "hours_per_100k": round(secs / n * 100_000 / 3600, 1),
            "completed": completed,
            "dns_failed": dns_failed,
            "other_failed": n - completed - dns_failed,
            "tls13_errors": r["tls13_status_counts"].get("ERROR", 0),
            "tls12_errors": r["tls12_status_counts"].get("ERROR", 0),
        })
    return pd.DataFrame(rows)

def main():
    records = load_run_records()
    if not records:
        print("No saved runs found in", RUNS_DIR)
        return
    df = summary_table(records)
    print(df.to_string(index=False))
    out = RUNS_DIR.parent / "runs_summary.csv"
    df.to_csv(out, index=False)
    print("Saved", out)

if __name__ == "__main__":
    main()