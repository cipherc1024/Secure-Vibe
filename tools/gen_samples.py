"""tools/gen_samples.py — Deterministic variant-expanded self-test sample generator.

Pipeline:
  BASES (tools/gen_bases.py, 153 verified rule id bases)
    -> deterministic text transforms (comments / wrapping / blanks / renames /
       quote flipping / trailing lines)
    -> empirical self-filter: a positive variant is kept only if the target rule
       still fires; a negative variant is kept only if it stays 0-violation
    -> tests/generated_samples.json (committed artifact)

Reproducible: no timestamps, fixed ordering, fixed seed. Re-running the
generator must byte-for-byte reproduce the committed JSON.

Usage:
    py -3 tools/gen_samples.py            # regenerate + verify + write
    py -3 tools/gen_samples.py --min 2000 # override minimum sample count

Exit 0 on success, 1 when the filtered result drops below --min.
Console output is ASCII-only (GBK safe).
"""
from __future__ import annotations

import argparse
import json
import keyword
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from core.validator import Validator  # noqa: E402
from gen_bases import BASES, DEAD_RULES  # noqa: E402

OUT = ROOT / "tests" / "generated_samples.json"

# --------------------------------------------------------------------------
# transform primitives (pure text; faithfulness is delegated to the filter)
# --------------------------------------------------------------------------

_PY_PROTECT = set(keyword.kwlist) | {
    "input", "request", "os", "sys", "self", "True", "False", "None",
    "eval", "exec", "open", "import", "from",
}

# rule-critical call names: never renamed so positive variants survive
_PROTECT_NAMES = {
    "system", "popen", "sprintf", "strcpy", "strcat", "scanf", "rand",
    "mktemp", "gets", "printf", "eval", "exec", "pickle", "yaml", "md5",
    "sha1", "ssl", "urandom", "parse", "fromstring", "setup_comment",
}

COMMENT = {
    "python": "# variant noise\n# generated sample\n",
    "js": "// variant noise\n// generated sample\n",
    "java": "// variant noise\n// generated sample\n",
    "go": "// variant noise\n// generated sample\n",
    "c": "// variant noise\n// generated sample\n",
    "cpp": "// variant noise\n// generated sample\n",
    "php": "// variant noise\n// generated sample\n",
    "sh": "# variant noise\n# generated sample\n",
    "html": "<!-- variant noise -->\n",
    "dockerfile": "# variant noise\n# generated sample\n",
    "kubernetes": "# variant noise\n# generated sample\n",
    "terraform": "# variant noise\n# generated sample\n",
    "github-actions": "# variant noise\n# generated sample\n",
}

TAIL = {
    "python": "x = 0",
    "js": "const x = 0;",
    "java": "int x = 0;",
    "go": "var x = 0",
    "c": "return 0;",
    "cpp": "return 0;",
    "php": "$x = 0;",
    "sh": "true",
    "html": "<span>ok</span>",
    "dockerfile": "# tail",
    "kubernetes": "  labels:\n    sv: generated",
    "terraform": "  tags = {}",
    "github-actions": "      - name: tail",
}


def _indent(code: str, n: int) -> str:
    pad = " " * n
    return "\n".join((pad + line if line.strip() else "") for line in code.splitlines())


def t_noise(lang: str, code: str) -> str:
    prefix = COMMENT.get(lang, "# noise\n")
    if code.lstrip().startswith(prefix.strip().splitlines()[0].lstrip()):
        return code
    return prefix + code


def t_blank(lang: str, code: str) -> str:
    if "\n" not in code:
        return code
    return code.replace("\n", "\n\n", 1)


def t_wrap(lang: str, code: str) -> str | None:
    c = code.strip()
    if lang == "python":
        if c.startswith(("def ", "class ")):
            return None
        return "def __sv_variant():\n" + _indent(code, 4) + "\n"
    if lang == "js":
        if c.startswith(("class ", "function ")):
            return None
        return "function sv_variant() {\n" + _indent(code, 2) + "\n}\n"
    if lang == "java":
        if "class " in c:
            return None
        return "class SVV {\n    static void run() {\n" + _indent(code, 8) + "\n    }\n}\n"
    if lang in ("c", "cpp"):
        return "void sv_variant(void) {\n" + _indent(code, 2) + "\n}\n\nint main(void) { sv_variant(); return 0; }\n"
    if lang == "go":
        return "func sv_variant() {\n" + _indent(code, 1) + "\n}\n"
    if lang == "php":
        if c.startswith("<?php"):
            return None
        return "<?php\nfunction sv_variant() {\n" + _indent(code, 2) + "\n}\n"
    if lang == "sh":
        return "sv_variant() {\n" + _indent(code, 2) + "\n}\n"
    if lang == "html":
        return "<div>\n" + code + "\n</div>\n"
    if lang == "dockerfile":
        return "FROM alpine:3.20\nWORKDIR /app\n" + code
    if lang == "kubernetes":
        return ("apiVersion: v1\nkind: Pod\nmetadata:\n  name: sv\nspec:\n"
                + _indent(code, 2) + "\n")
    if lang == "terraform":
        return 'resource "sv_block" "sv" {\n' + _indent(code, 2) + "\n}\n"
    if lang == "github-actions":
        return ("name: sv\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      -\n" + _indent(code, 8) + "\n")
    return None


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def t_rename(lang: str, code: str) -> str | None:
    protect = (_PY_PROTECT if lang == "python" else set()) | _PROTECT_NAMES
    hits: list[str] = []

    def repl(m: re.Match) -> str:
        tok = m.group(0)
        if tok in protect or len(tok) < 2:
            return tok
        hits.append(tok)
        return tok + "_sv2"

    out = _IDENT.sub(repl, code)
    if not hits or out == code:
        return None
    return out


_DQ = re.compile(r'"([^"\'`\\\n]{2,})"')


def t_quote(lang: str, code: str) -> str | None:
    if lang not in ("python", "js"):
        return None
    out = _DQ.sub(lambda m: "'%s'" % m.group(1), code)
    if out == code:
        return None
    return out


def t_tail(lang: str, code: str) -> str:
    return code.rstrip("\n") + "\n" + TAIL.get(lang, "") + "\n"


def t_dup(lang: str, code: str) -> str:
    return code.rstrip("\n") + "\n" + code


_INDENT_OK = {"html", "dockerfile", "kubernetes", "terraform", "github-actions", "sh"}


def t_indent(lang: str, code: str) -> str | None:
    if lang not in _INDENT_OK:
        return None
    return _indent(code, 2)


_EOL_MARK = {
    "python": "#", "sh": "#", "dockerfile": "#", "kubernetes": "#",
    "terraform": "#", "github-actions": "#", "js": "//", "java": "//",
    "go": "//", "c": "//", "cpp": "//", "php": "//",
}


def t_eol(lang: str, code: str) -> str | None:
    marker = _EOL_MARK.get(lang)
    if marker is None or "\n" in code:
        return None
    return code.rstrip() + "  " + marker + " variant"


def _composite_wrap_noise(lang: str, code: str) -> str | None:
    w = t_wrap(lang, code)
    if w is None:
        return None
    return t_noise(lang, w)


# --------------------------------------------------------------------------
# generation + empirical self-filter
# --------------------------------------------------------------------------

def _language_bump(lang: str) -> str:
    return {"nodejs": "js", "workflow": "github-actions", "docker": "dockerfile",
            "bash": "sh"}.get(lang, lang)


def generate() -> tuple[list[dict], dict]:
    samples: list[dict] = []
    stats: dict = {"bases": 0, "raw": 0, "kept_pos": 0, "kept_neg": 0,
                   "dropped_pos": 0, "dropped_neg": 0}
    validators: dict[str, Validator] = {}
    seen: set[tuple[str, str]] = set()

    def validator_for(lang: str) -> Validator:
        v = validators.get(lang)
        if v is None:
            v = Validator(language=lang)
            validators[lang] = v
        return v

    def keep(language: str, code: str, should_flag: bool, note: str,
             rule_id: str, want_rule: bool) -> None:
        key = (language, code)
        if key in seen:
            return
        seen.add(key)
        v = validator_for(language)
        try:
            r = v.validate(code)
        except Exception:  # unparsable variant: drop
            return
        fired = {x.rule_id for x in r.violations}
        if should_flag:
            ok = bool(r.violations)
            if want_rule:
                ok = ok and rule_id in fired
            if ok:
                samples.append({"language": language, "code": code,
                                "should_flag": True, "note": note})
                stats["kept_pos"] += 1
            else:
                stats["dropped_pos"] += 1
        else:
            if not r.violations:
                samples.append({"language": language, "code": code,
                                "should_flag": False, "note": note})
                stats["kept_neg"] += 1
            else:
                stats["dropped_neg"] += 1

    for rule_id in sorted(BASES):
        language, pos, negs = BASES[rule_id]
        lang = _language_bump(language)
        stats["bases"] += 1
        dead = rule_id in DEAD_RULES

        if not dead:
            keep(lang, pos, True, f"{rule_id}:base-pos", rule_id, True)
        for tag, fn in [("pos-noise", t_noise), ("pos-wrap", t_wrap),
                        ("pos-blank", t_blank), ("pos-rename", t_rename),
                        ("pos-quote", t_quote), ("pos-tail", t_tail),
                        ("pos-wrapnoise", _composite_wrap_noise),
                        ("pos-dup", t_dup), ("pos-indent", t_indent),
                        ("pos-eol", t_eol)]:
            if dead:
                break
            variant = fn(lang, pos)
            if variant is None:
                continue
            keep(lang, variant, True, f"{rule_id}:{tag}", rule_id, True)

        for i, neg in enumerate(negs if isinstance(negs, list) else [negs]):
            keep(lang, neg, False, f"{rule_id}:neg{i}-base", rule_id, False)
            for tag, fn in [("neg-noise", t_noise), ("neg-wrap", t_wrap),
                            ("neg-blank", t_blank), ("neg-rename", t_rename),
                            ("neg-quote", t_quote), ("neg-tail", t_tail),
                            ("neg-wrapnoise", _composite_wrap_noise),
                            ("neg-dup", t_dup), ("neg-indent", t_indent),
                            ("neg-eol", t_eol)]:
                variant = fn(lang, neg)
                if variant is None:
                    continue
                keep(lang, variant, False, f"{rule_id}:neg{i}-{tag}", rule_id, False)

    samples.sort(key=lambda s: (s["note"].split(":", 1)[0], s["note"], s["code"]))
    stats["raw"] = len(samples)
    return samples, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min", type=int, default=2000,
                    help="minimum total samples the filtered result must contain")
    args = ap.parse_args()

    samples, stats = generate()
    payload = {
        "generator": "tools/gen_samples.py",
        "schema": "positive/negative self-test samples (language, code, should_flag, note)",
        "min_total": args.min,
        "total": len(samples),
        "note": ("committed artifact; regenerate with tools/gen_samples.py then run "
                 "pytest tests/test_generated_samples.py"),
        "samples": samples,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=True, indent=None), encoding="utf-8")

    print("gen_samples summary:")
    print(f"  bases: {stats['bases']}")
    print(f"  kept pos: {stats['kept_pos']} (dropped {stats['dropped_pos']})")
    print(f"  kept neg: {stats['kept_neg']} (dropped {stats['dropped_neg']})")
    print(f"  wrote: {OUT.relative_to(ROOT)} total={len(samples)} min={args.min}")
    if len(samples) < args.min:
        print(f"FAIL: under minimum sample count ({len(samples)} < {args.min})")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
