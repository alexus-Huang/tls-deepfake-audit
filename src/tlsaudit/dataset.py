"""Build the composite domain dataset (benign + threat-intel groups)."""
import csv
import re
from pathlib import Path

import pandas as pd

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})"
HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+{_TLD}$")


def normalize_domain(raw):
    """Return a clean lowercase hostname, or None if unusable.

    Rejects comments, URLs, paths, ports, and IP addresses so we only
    probe plain hostnames.
    """
    if raw is None:
        return None
    s = raw.strip().lower().replace("[.]", ".").rstrip(".")
    if not s or s.startswith("#"):
        return None
    return s if HOSTNAME_RE.match(s) else None


def read_domain_file(path):
    """Read a one-domain-per-line file. Missing file -> empty list."""
    path = Path(path)
    if not path.exists():
        return []
    seen, out = set(), []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        d = normalize_domain(line)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def load_tranco(path, limit=500):
    """Read the first `limit` valid domains from a Tranco 'rank,domain' CSV."""
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 2:
                continue
            d = normalize_domain(row[1])
            if d and d not in out:
                out.append(d)
            if len(out) >= limit:
                break
    return out


def build_dataset(tranco_path, threat_files, limit=500):
    """Return a DataFrame with columns: domain, group, source.

    threat_files maps group name -> file path. Domains appearing in more
    than one group are ambiguous and are dropped entirely.
    """
    rows = [(d, "benign", "tranco") for d in load_tranco(tranco_path, limit)]
    for group, p in threat_files.items():
        rows += [(d, group, Path(p).name) for d in read_domain_file(p)]
    df = pd.DataFrame(rows, columns=["domain", "group", "source"])
    return df.drop_duplicates(subset="domain", keep=False).reset_index(drop=True)