"""tools/verify_bases.py — Empirical verification harness for tools/gen_bases.py.

For every rule id in gen_bases.BASES:
  positive: Validator(language).validate(pos) must contain a violation with that rule_id
  negative: validate(neg) must return ZERO violations (strict, any rule)

Usage:
    py -3 tools/verify_bases.py [--only PY-001] [--only BL-001,JS-001]

Exit 0 when all verified, 1 otherwise. Console output is ASCII-only (GBK safe).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.validator import Validator  # noqa: E402
from gen_bases import BASES, DEAD_RULES  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="comma-separated rule ids to check")
    args = ap.parse_args()
    only = {s.strip() for s in args.only.split(",") if s.strip()}

    validators: dict[str, Validator] = {}
    verified = 0
    failed: list[str] = []
    checked = 0

    for rule_id in sorted(BASES):
        if only and rule_id not in only:
            continue
        language, pos, negs = BASES[rule_id]
        if isinstance(negs, str):  # defensive: entries must use lists
            negs = [negs]
        v = validators.get(language)
        if v is None:
            v = Validator(language=language)
            validators[language] = v

        problems: list[str] = []
        r = v.validate(pos)
        fired = {x.rule_id for x in r.violations}
        is_dead = rule_id in DEAD_RULES
        if rule_id not in fired and not is_dead:
            problems.append(f"pos missing {rule_id} (fired: {sorted(fired) or 'none'})")
        for i, neg in enumerate(negs):
            rn = v.validate(neg)
            if rn.violations:
                ids = sorted({x.rule_id for x in rn.violations})
                problems.append(f"neg[{i}] fired {ids}")

        checked += 1
        if problems:
            failed.append(rule_id)
            print(f"FAIL {rule_id} ({language})")
            for p in problems:
                print(f"     {p}")
        else:
            verified += 1
            flag = " (pos dead-skipped)" if is_dead else ""
            print(f"PASS {rule_id} ({language}){flag}")

    print(f"verified {verified}/{checked}, failed {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
