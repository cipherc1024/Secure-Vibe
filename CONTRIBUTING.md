# Contributing to Secure-Vibe

Thanks for contributing! This document covers the two most common contribution
types: adding detection rules and changing the validator/repair engines.

## Adding a detection rule

Rules live in YAML lists under `rules/<language>.yaml` (and
`blacklist/<language>.yaml` for deprecated-API call patterns). One entry per
vulnerability:

```yaml
- id: PY-054
  name: tls_verify_false
  severity: high
  cwe: CWE-295
  message: "One-line English explanation | 一句话中文说明"
  fix_hint: "Concrete remediation the repair loop can apply. | 修复建议。"
  template: ""            # optional: safe replacement snippet for template repair
  match:
    regex:
      - >-
        (?i)(requests|httpx|urllib3)\.\w+\s*\([^)]*verify\s*=\s*False
    exclude_regex:
      - >-
        \bverify\s*=\s*True
```

### Field requirements

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | `<LANG>-<NNN>`, unique across the pack (PY-001, JS-003, …) |
| `name` | yes | lowercase snake_case; also links to `deterministic_fix` if applicable |
| `severity` | yes | `high` / `medium` / `low` |
| `cwe` | yes | the most specific CWE id (`cwe_reference.yaml` is the vocabulary) |
| `message` | yes | English + Chinese, `|` separated |
| `fix_hint` | yes | actionable advice, English + Chinese |
| `match` | yes | any of `ast_calls`, `ast_kwargs`, `regex` (see `core/validator.py` Rule docstring) |
| `exclude_regex` | strongly advised | pattern that makes the rule NOT fire; keeps the FP baseline at 0% |

### Match-method guidance

- Prefer `ast_calls` / `ast_kwargs` when the danger is a specific call — they are
  immune to comments and string contents. Use `regex` only for patterns the AST
  cannot express (connection-string charsets, `verify=False`, …).
- Cross-line patterns: add `multiline: true` under `match` to run the regex
  against the whole source (line numbers recovered from match offsets). This is
  opt-in; the default line-by-line scan keeps false positives at 0%.

### Test requirements

1. `python tools/rule_stats.py` — totals must stay in sync with README/docs.
2. Add a malicious sample that fires the rule AND a benign sample that must NOT
   fire it, then run:

   ```
   python -m pytest tests/ -q
   ```

3. Run the self-check: `python cli.py selftest` must stay green.
4. Scan this repo: `python cli.py sast . ` must report 0 findings (your rule
   must not fire on our own rule files, docstrings, or tests).

## Changing the validator / repair engines

- `core/validator.py` — checkers, rule loading, suppression (`secure-vibe: ignore`).
- `core/taint.py` — lightweight Python taint analysis; sanitizer allowlist is
  extendable via `config.yaml validator.sanitizers` or `register_sanitizers()`.
- `core/ast_fixer.py` — deterministic rewrites; a rule name must be listed in
  `deterministic_fix`'s fixable set before its fixer runs.
- `cli.py` — CLI surface, config loading (`_apply_config_sanitizers`,
  `_load_config`).

Run the full gate before submitting:

```
python -m pytest tests/ -q
python cli.py selftest
python cli.py sast . --fail-on high
```

## Ground rules

- stdlib + pyyaml only for the core path; optional deep engines (semgrep,
  pip-audit) must stay optional (`requirements.txt`, `Dockerfile`).
- Never weaken an existing rule without a test that documents why the old
  pattern was a false positive.
- Keep messages bilingual; keep IDs stable — downstream users grep for them.
