# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.3] - 2026-09-10

Multi-language AST plan (phases 1–3) complete: 11 new js/java line rules,
an optional tree-sitter call engine, and cross-statement taint for js/java.
Rules **118 → 129** (+13 blacklists); selftest suite 68 samples, 48/48
detected at **0% false positives**.

### Phase 3: js/java cross-statement taint-lite

- `core/taint_ml.py`: statement-ordered taint map per function scope on top of
  tree-sitter. Sources — js `req.query/body/params/cookies`, `process.argv`,
  `location.*`; java `*request.getParameter/getParameterValues/getHeader`.
  Sinks — js `child_process exec/execSync`, `res.send/end/write`,
  `res.redirect`, `fs.*` file ops, `*.query/execute`; java
  `Runtime.getRuntime().exec`, `new ProcessBuilder`, JDBC
  `executeQuery/executeUpdate/execute`. Sanitizer allowlists
  (encodeURIComponent/escapeHtml/…, Jsoup.clean/…) kill taint; reassignment
  clears it; each function body is its own scope. Findings carry the
  provenance chain (source → var → sink) and replace shallow regex hits on the
  same (rule_id, line).
- `core/xast.py`: cached `parse(code, language)` entry for the js+java
  grammars; tree-sitter-javascript service: function bodies are
  `statement_block` (not `block`).
- 18 new tests (`tests/test_taint_ml.py`): cross-statement js/java flows,
  sanitizer kills, reassignment clears, scope isolation, template
  0-FP re-check, degradation when tree-sitter is absent.

### Phase 1+2 of the multi-language AST plan

#### Added

- js/java line-level rules: JS-010–JS-017 (SQL template literals, TLS
  `rejectUnauthorized: false`, weak hash MD5/SHA1, `Math.random` tokens,
  hardcoded credentials, open redirect, fs path traversal, JWT `alg: none`);
  JAVA-008–JAVA-010 (weak hash, trust-all TrustManager/HostnameVerifier,
  hardcoded credentials). Rules total 118 → 129 (+13 blacklist).
- Optional tree-sitter AST engine for js/java (`core/xast.py`): rules can use
  `match.xast` ({call, arg, arg_index}) for precise call matching
  (JS-001 eval/new Function, JS-004 string timer, JS-009 dynamic require).
  The engine is additive — absent locally → silent fallback to regex; ships
  in the Docker image; java grammar lands with phase 3.
- 12 new self-test samples (js/java); suite now 68 samples, 48/48 detected,
  0 false positives.

#### Changed

- README coverage table updated (131 → 142 rules); CONTRIBUTING.md documents
  the `xast` block; requirements.txt/Dockerfile carry the optional
  tree-sitter dependencies.

## [1.1.2] - 2026-09-09

Evaluation-report improvements: configurable sanitizers, a new fix + rule for
disabled TLS verification, opt-in cross-line matching, container packaging and
contributor docs. Detection stays at **81.8%** with **0% false positives**.

### Added

- Configurable sanitizer allowlist: `config.yaml validator.sanitizers` (or
  `register_sanitizers()`) merges extra sanitizer functions into the taint
  engine; cli.py applies config values before every validate/sast run.
- PY-054 `tls_verify_disabled` rule (CWE-295): flags
  `requests/httpx/urllib3` calls with `verify=False`, with an
  `exclude_regex` guard for `verify=True`.
- 8th deterministic fix `tls_verify_false`: rewrites `verify=False` to
  `verify=True` (all fixes re-validated after applying).
- Opt-in cross-line matching: `match.multiline: true` runs a rule's regex
  against the whole source with line numbers recovered from match offsets;
  line-by-line scanning remains the default to keep false positives at 0%.
- `Dockerfile`: one-shot deep-scan image including the optional engines
  (semgrep, pip-audit) that native installs treat as best-effort.
- `CONTRIBUTING.md`: rule-writing spec (ids, CWE, regex + exclusions, match
  methods, test requirements) and the full gate for engine changes.
- `tools/rule_stats.py`: per-file rule/blacklist counts (verifies the
  README/docs totals, currently 118 + 13 = 131).

### Changed

- JSON output robustness on Windows: piped stdout emits pure-ASCII JSON
  (`\uXXXX` escapes, valid JSON with identical data); interactive TTYs keep
  readable UTF-8. Guards against GBK-decoding garbled text in PS 5.1 pipes.
- `config.yaml` version synced to 1.1.2 (was 1.1.0).

### Fixed

- `core/taint.py`: `register_sanitizers()` raised AttributeError on the
  frozenset allowlist (silently swallowed by config loading); the allowlist
  is now a mutable set.

## [1.1.1] - 2026-09-09

Security-focused engine expansion: SecurityEval detection **38.0% → 81.8%** at
**0% false positives**. Rules count **97 → 131**.

### Added

- Taint engine expansion (`core/taint.py`): new confirmed sinks — open redirect,
  reflected response writes, header injection (including Django-style
  `response['Location'] = tainted` assignment), log injection, ReDoS `re.compile`,
  XPath/LDAP/NoSQL filter calls, file read/write, XML parse; new taint sources for
  `request.args['x']` subscript and direct-call forms; Attribute/Subscript
  propagation (`p.filename` inherits the base object's taint — recovers the
  CWE-434 file-upload misses).
- Sanitizer modeling (`core/taint.py`): taint is killed at `html.escape`,
  `shlex.quote`, `secure_filename`, `urllib.parse.quote`, `re.escape` and
  int/float/bool coercion boundaries — fewer false positives on sanitized code.
- 21 new rules (`rules/python.yaml`): PY-033–PY-053 — weak crypto, unsafe tar
  extract, JWT verify, XXE parse (defusedxml-aware), hardcoded credentials /
  IV / salt / API keys / DB credentials, traceback info leak (CWE-209),
  NoSQL filter-expression concatenation (CWE-943); PY-004 now covers
  `cPickle`/`_pickle` variants. Alias imports (`from X import Y as Z`),
  `shell=bool()` calls, list-form `sh -c` subprocesses and SQL quote-concat are
  now detected.
- 3 new deterministic fixes (`core/ast_fixer.py`): `shell=True` string command →
  argument list, `%s`-concat SQL → parameterized query, tainted path concat →
  `os.path.join` + `os.path.basename` (7 total, all re-validated after applying).
- Server hardening (`server.py`): rejects non-loopback Host headers
  (DNS-rebinding guard), optional bearer token (`SECURE_VIBE_SERVER_TOKEN`),
  serialized backend env override.
- Installer safety (`install.sh` / `install.ps1`): refuse protected targets
  (drive root / home directory) before any destructive cleanup; copy `hooks/`
  so the pre-commit gate works on installed copies.
- Log masking (`core/logger.py`): AWS secret/session keys and JWTs are masked in
  JSONL audit logs.

### Changed

- GEN-005 no longer flags parameterized `execute(sql, params)` forms — the
  exclusion list recognizes tuple/list arguments, so safe SQL is not reported.
- Cross-engine dedupe in the validator: shallow ast/regex hits on the same
  (rule_id, line) yield to taint conclusions.
- `require_regex` rule field: regex rules can require a second pattern
  (for docstring-embedded samples).
- README/docs updated with the measured numbers and an honest boundary note
  (taint sanitizers are a fixed allowlist, not proven).

### Measured

- SecurityEval (MSR4P&S'22, full official dataset): **detection 81.8% (99/121) /
  false positives 0.0% / ~1.4 ms** (baseline at v1.1.0: 38.0%); the remaining
  ~20 misses are interprocedural/semantic CWEs (SSRF via function parameters,
  missing-auth logic) delegated to the `sast` orchestrator (semgrep/CodeQL).
- Test suite: 255 passing.

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

[1.1.3]: https://github.com/cipherc1024/Secure-Vibe/releases/tag/v1.1.3
[1.1.2]: https://github.com/cipherc1024/Secure-Vibe/releases/tag/v1.1.2
[1.1.1]: https://github.com/cipherc1024/Secure-Vibe/releases/tag/v1.1.1
[1.1.0]: https://github.com/cipherc1024/Secure-Vibe/releases/tag/v1.1.0
[1.0.0]: https://github.com/cipherc1024/Secure-Vibe/releases/tag/v1.0.0
