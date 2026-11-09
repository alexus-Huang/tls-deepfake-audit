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

_SPLIT_RE = re.compile(r"[,\t; ]+")

def load_exclusions(path):
    """Read an exclusion list. Returns (exact_names, suffixes).

    'example.com' blocks that exact name. '.gov.uk' blocks gov.uk and all its subdomains.
    A missing file means no exclusions.
    """
    path = Path(path)
    if not path.exists():
        return set(), set()
    exact, suffixes = set(), set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().lower().replace("[.]", ".")
        if not line or line.startswith("#"):
            continue
        if line.startswith("."):
            suffixes.add(line)
        else:
            name = normalize_domain(line)
            if name:
                exact.add(name)
    return exact, suffixes


def is_excluded(domain, exact, suffixes):
    if domain in exact:
        return True
    return any(domain == s[1:] or domain.endswith(s) for s in suffixes)


def load_domains(path, limit=None, skip=0, exclude=None, excluded=None):
    """Read domains from a .txt or .csv file with any column layout.

    Each non-empty, non-comment line is split on commas, tabs, semicolons,
    and spaces. The first cell that is a plain hostname is used. Header rows,
    URLs, and IP addresses are rejected and counted.
    `exclude` is an (exact, suffixes) pair from load_exclusions. Excluded names are
    dropped before limit/skip are counted, and are appended to the `excluded` list.
    Returns (domains, rejected_lines).
    """
    wanted = None if limit is None else skip + limit
    seen, out, rejected = set(), [], 0
    with open(path, encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain = None
            for cell in _SPLIT_RE.split(line):
                domain = normalize_domain(cell.strip("\"'"))
                if domain:
                    break
            if not domain:
                rejected += 1
            elif domain not in seen:
                seen.add(domain)
                if exclude and is_excluded(domain, *exclude):
                    if excluded is not None:
                        excluded.append(domain)
                    continue
                out.append(domain)
                if wanted is not None and len(out) >= wanted:
                    break
    return out[skip:], rejected