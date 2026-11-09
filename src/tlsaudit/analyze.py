"""Answer the research question from saved runs: which cipher suites do hosts accept?"""
import json
import sys
from collections import Counter
from pathlib import Path
import pandas as pd
from .runner import RUNS_DIR
LEGACY_MARKERS = ("_CBC_", "_3DES_", "_RC4_", "_NULL_", "EXPORT", "_anon_", "_MD5")

def suite_flags(name):
    flags = []
    if name.startswith(("TLS_RSA_WITH_", "TLS_RSA_EXPORT_")):
        flags.append("no_forward_secrecy")
    if any(marker in name for marker in LEGACY_MARKERS):
        flags.append("legacy_by_name")
    return flags

def load_records(run_dirs):
    records = []
    for d in run_dirs:
        path = Path(d) / "results.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records

def version_summary(records, field):
    scanned = [r[field] for r in records if r.get(field) is not None]
    supporting = [s for s in scanned if s]
    counts = Counter()
    for suites in supporting:
        counts.update(set(suites))
    return {"hosts_scanned": len(scanned), "hosts_supporting": len(supporting),
            "suite_counts": counts}

def suite_table(summary):
    n = summary["hosts_supporting"]
    rows = [{"suite": s, "hosts": c,
             "percent_of_supporting": round(100 * c / n, 1) if n else 0.0,
             "flags": ",".join(suite_flags(s))}
            for s, c in summary["suite_counts"].most_common()]
    return pd.DataFrame(rows, columns=["suite", "hosts", "percent_of_supporting", "flags"])

def overview(records):
    status = Counter(r.get("connectivity_status") or "NONE" for r in records)
    days = [r["validity_days"] for r in records if r.get("validity_days") is not None]
    issuers = Counter(r["issuer"] for r in records if r.get("issuer"))
    return {"domains": len(records), "status": dict(status),
            "validity_days": (min(days), int(pd.Series(days).median()), max(days)) if days else None,
            "top_issuers": issuers.most_common(5)}

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        run_dirs = [Path(a) for a in argv]
    else:
        found = sorted(RUNS_DIR.glob("*/results.jsonl"))
        if not found:
            print("No saved runs in", RUNS_DIR)
            return 1
        run_dirs = [found[-1].parent]
    records = load_records(run_dirs)
    print("Runs:", ", ".join(d.name for d in run_dirs))
    print(overview(records))
    for label, field in (("TLS 1.3", "tls13_accepted_ciphers"), ("TLS 1.2", "tls12_accepted_ciphers")):
        summary = version_summary(records, field)
        print(f"\n{label}: scanned {summary['hosts_scanned']} hosts, "
              f"{summary['hosts_supporting']} accept at least one suite")
        if summary["hosts_scanned"]:
            table = suite_table(summary)
            print(table.head(15).to_string(index=False))
            out = run_dirs[-1] / f"suites_{field[:5]}.csv"
            table.to_csv(out, index=False)
            print("All rows saved to", out)
    return 0

if __name__ == "__main__":
    sys.exit(main())