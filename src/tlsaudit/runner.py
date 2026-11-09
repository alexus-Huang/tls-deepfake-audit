"""Run a safety-limited scan. Every run is saved in its own folder"""
import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

from .config import ScanConfig
from .dataset import load_domains, load_exclusions
from .scanner import scan_domains

RUNS_DIR = Path("data/results/runs")
ATTEMPTS_PER_HOST_TLS13 = 6
ATTEMPTS_PER_HOST_TLS12 = 158


def run_folder_name(label, started):
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in label)
    return f"{started.strftime('%Y%m%d-%H%M%S')}_{safe}"

def count_field(results_path, field):
    """Count the values of one field across a results.jsonl file."""
    path = Path(results_path)
    counts = Counter()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                counts[json.loads(line).get(field) or "NONE"] += 1
    return dict(counts)

def main(argv=None):
    p = argparse.ArgumentParser(description="Run a safety-limited TLS scan and save the run.")
    p.add_argument("--domains", required=True, help="domain list file (.txt or .csv)")
    p.add_argument("--limit", type=int, default=None, help="scan at most N domains")
    p.add_argument("--skip", type=int, default=0, help="skip the first N valid domains (chunked runs)")
    p.add_argument("--timeout", type=int, default=5, help="connect timeout in seconds (1-10)")
    p.add_argument("--tls12", action="store_true", help="also enumerate TLS 1.2 ciphers")
    p.add_argument("--network", required=True, help="network label, e.g. ResWiFi")
    p.add_argument("--label", default="run", help="short name for this run")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.add_argument("--exclude", default="data/raw/exclude.txt", help="exclusion list (names, or .suffix lines)")
    args = p.parse_args(argv)

    try:
        cfg = ScanConfig(connect_timeout=args.timeout)   # refuses values above the ceilings
    except ValueError as exc:
        p.error(str(exc))

    exclusions = load_exclusions(args.exclude)
    excluded = []
    domains, rejected = load_domains(args.domains, args.limit, args.skip, exclusions, excluded)
    if not domains:
        print("No valid domains found. Nothing was sent.")
        return 1

    per_host = ATTEMPTS_PER_HOST_TLS13 + (ATTEMPTS_PER_HOST_TLS12 if args.tls12 else 0)
    print(f"Domains: {len(domains)} (rejected lines: {rejected}) from {Path(args.domains).name}")
    print(f"Excluded by {Path(args.exclude).name}: {len(excluded)} {excluded[:5]}")
    print(f"TLS 1.2: {'ON' if args.tls12 else 'off'} | timeout {cfg.connect_timeout} s | "
          f"{cfg.parallel_hosts} hosts at once, {cfg.connections_per_host} connections per host, 1 attempt")
    print(f"Roughly {len(domains) * per_host:,} connection attempts in total ({per_host} per host).")
    if not args.yes and input("Type YES to send traffic to these domains: ").strip() != "YES":
        print("Cancelled. Nothing was sent.")
        return 0

    started = datetime.now().astimezone()
    run_dir = RUNS_DIR / run_folder_name(args.label, started)
    run_dir.mkdir(parents=True, exist_ok=False)
    results = run_dir / "results.jsonl"

    t0 = time.time()
    scan_domains(domains, results, cfg, include_tls12=args.tls12)
    seconds = time.time() - t0

    info = {
        "label": args.label,
        "started_local": started.isoformat(timespec="seconds"),
        "started_utc": started.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "network": args.network,
        "dataset_file": Path(args.domains).name,
        "skip": args.skip,
        "limit": args.limit,
        "domains_scanned": len(domains),
        "rejected_lines": rejected,
        "tls12_enabled": args.tls12,
        "timeout_seconds": cfg.connect_timeout,
        "parallel_hosts": cfg.parallel_hosts,
        "connections_per_host": cfg.connections_per_host,
        "attempts_per_connection": cfg.max_retries + 1,
        "sslyze_version": version("sslyze"),
        "duration_seconds": round(seconds, 2),
        "status_counts": count_field(results, "connectivity_status"),
        "tls13_status_counts": count_field(results, "tls13_status"),
        "tls12_status_counts": count_field(results, "tls12_status"),
        "exclude_file": Path(args.exclude).name,
        "excluded_domains": excluded,
    }
    (run_dir / "run.json").write_text(json.dumps(info, indent=2), encoding="utf-8")

    print(f"Done: {len(domains)} domains in {seconds:.1f} s ({seconds / len(domains):.3f} s per host)")
    print("Statuses:", info["status_counts"])
    print("Saved to:", run_dir)
    return 0

if __name__ == "__main__":
    sys.exit(main())