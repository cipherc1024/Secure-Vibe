#!/usr/bin/env python3
"""Count detection rules and blacklist entries across the rule packs.

Usage:
    python tools/rule_stats.py
    python tools/rule_stats.py --json

Prints a per-file breakdown (rules/*.yaml and blacklist/*.yaml) and totals,
so README/docs numbers can be verified after every rule change.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKS = {"rules": "rules", "blacklist": "blacklist"}


def _load(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def _rule_id(entry: dict) -> str:
    return str(entry.get("id", "<no-id>"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    rows: list[dict] = []
    for pack, sub in PACKS.items():
        d = REPO_ROOT / sub
        for path in sorted(d.glob("*.yaml")):
            if path.name == "cwe_reference.yaml":
                continue  # reference data, not detection rules
            entries = _load(path)
            rows.append({
                "pack": pack,
                "file": path.name,
                "count": len(entries),
                "ids": [_rule_id(e) for e in entries],
            })

    total_rules = sum(r["count"] for r in rows if r["pack"] == "rules")
    total_blacklist = sum(r["count"] for r in rows if r["pack"] == "blacklist")

    if args.json:
        print(json.dumps({
            "rules_total": total_rules,
            "blacklist_total": total_blacklist,
            "total": total_rules + total_blacklist,
            "files": rows,
        }, indent=2))
        return 0

    for pack in ("rules", "blacklist"):
        print(f"[{pack}]")
        for r in (x for x in rows if x["pack"] == pack):
            print(f"  {r['file']:<22} {r['count']:>3}")
    print(f"\nrules: {total_rules}  blacklist: {total_blacklist}  total: {total_rules + total_blacklist}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
