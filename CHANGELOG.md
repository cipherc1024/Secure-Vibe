# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-09-07

Repositioned from "secure-by-generation guarantee" to a honest **fast lint + engine
orchestrator + commit gate** (dropped unverifiable claims about interprocedural
analysis / runtime protection / ops).

### Added

- Lexical stripping (`core/strip.py`): python tokenize + js lexer strip comments and
  strings before regex matching — comment/docstring/string contents never trigger rules.
- SAST orchestrator (`core/sast.py` + `cli.py sast`): one pass over a directory running
  the built-in engine + semgrep (auto-installed in CI, graceful degrade locally) +
  pip-audit / govulncheck / npm audit, normalized into a single finding shape,
  `--fail-on high|any|never`.
- Commit gate: `hooks/pre-commit` + `.pre-commit-config.yaml` + `cli.py precommit
  [--all|--install-hook]`; the hook resolves a usable interpreter (config.yaml
  `interpreter:` → PATH `python3`/`python`/`py -3`, accepting only ones that can import
  pyyaml) and skips cleanly when none is found — CI still gates on push.
- CI `sast` job (`.github/workflows/ci.yml`): ubuntu runner installing semgrep and
  scanning `core` + `tools`, fail-on high.
- Post-repair regression verification (`core/regression.py`): detects the project
  ecosystem (pytest/npm/go/cargo/make), re-runs the tests after a repair and reverts
  the change on failure; the repair loop records "reverted (regression failed)".
- Human review tickets (`repair_loop`): when the repair loop fails to converge, a full
  markdown ticket is emitted — original context, remaining violations with rule
  templates, alternatives, and round history (`review_dir`).
- 56-sample positive/negative self-test suite (`core/selftest_suite.py`), wired into
  `cli.py selftest` (39/39 flake-free target detections, 0 false positives).
- Startup self-check (`cli.py`): machine-specific fix commands instead of a bare
  traceback (finds configured interpreters, emits matching pip-install commands), plus
  an interpreter-mismatch warning; interpreter path cached in `config.yaml`.
- Line/file-level suppression: `# secure-vibe: ignore` (like noqa) and
  `# secure-vibe: ignore-file` (within the first 200 chars, for test fixtures/demo
  payloads).
- `literal_sensitive` rule flag: rules that inspect string *contents* match the raw
  line instead of the stripped shape (GEN-001/002/005/007, BL-005/007, PY-016/018,
  JS-005).

### Changed

- SecurityEval loader (`tools/run_evaluation.py`): parses the official `dataset.jsonl`
  format (`ID` / `Prompt` / `Insecure_code`) — two samples per line (insecure
  completion as positive, benign prompt as negative), CWE extracted from `ID`.
- Docs repositioned: README title/intro/trust section/roadmap/known-limits, SKILL.md
  mechanism facts, and `docs/evaluation.md` with the measured authoritative result.

### Measured

- SecurityEval (MSR4P&S'22, full official dataset: 121 insecure + 121 benign prompts):
  **detection 38.0% / false positives 0.0% / ~1.1 ms**.
- Test suite: 255 passing (Python 3.9 and 3.14 verified locally; CI matrix 3.10/3.11/3.12).

## [1.0.0] - 2026-09-05

### Added

- Initial release: `cli.py` (context / validate / repair / log / selftest / cwe /
  missed / export-repo), 13-language rule engine (AST dangerous calls + regex
  blacklists + Python taint), deterministic auto-repair (random→secrets, md5→sha256,
  yaml.load→safe_load, hardcoded secrets→env) + LLM local rewrite, JSONL audit trail
  with secret masking, bilingual rule content (EN/ZH), cross-agent installers
  (install.sh / install.ps1), CI test matrix, and the MIT-licensed docs set.

[1.1.0]: https://github.com/cipherc1024/Secure-Vibe/releases/tag/v1.1.0
[1.0.0]: https://github.com/cipherc1024/Secure-Vibe/releases/tag/v1.0.0
