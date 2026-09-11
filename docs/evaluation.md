# Secure-Vibe Professional Evaluation Guide

This project includes two levels of evaluation: **offline baseline** (runnable immediately) + **paper-grade benchmark** (requires a dataset).

## Offline Baseline (built-in, ready to use)

```bash
# Local benchmark: use the built-in malicious/safe test case set to compute detection rate / false positive rate / latency
python tools/benchmark.py
python tools/run_evaluation.py --local   # equivalent; outputs evaluation_report.json

# Current baseline (29 malicious + 22 safe cases):
#   detection_rate = 1.0, false_positive_rate = 0.0, avg_latency_ms ≈ 0.16
```

## Basic Evaluation (built-in, ready to use)

- `tests/test_validator.py`: per-rule test cases across the three engines (AST + regex + taint)
- `tests/test_repair_loop.py`: repair loop convergence, log completeness, Mock end-to-end
- Self-test: `python cli.py selftest` (curated 68-sample suite + generated variant suite)
- Rule bases: `python tools/verify_bases.py` — all 153 rule IDs have an empirically verified
  positive/negative base (positives trigger the target rule, negatives are 0-violation)
- Variant suite: `python tools/gen_samples.py` — deterministic expansion of the bases into
  `tests/generated_samples.json` (2378 faithful samples); `tests/test_generated_samples.py`
  pins the artifact (minimum volume, byte-for-byte regeneration, all samples faithful)

## Professional Evaluation (SecurityEval, requires downloading the dataset)

[SecurityEval](https://github.com/s2e-lab/SecurityEval) (MSR4P&S'22) is the standard evaluation set for secure code
generation, containing malicious code generation samples annotated with CWEs. It is used to measure the validator's
detection rate / false positive rate for this Skill, and to compare against published papers.

### Steps

```bash
# One-shot download of all external datasets (run when network access is available)
python tools/fetch_datasets.py --all --dir D:/datasets
# Or clone SecurityEval directly (the official repo)
git clone --depth 1 https://github.com/s2e-lab/SecurityEval.git D:/datasets/SecurityEval

# Configure config.yaml
evaluation:
  enabled: true
  securityeval_path: "D:/datasets/SecurityEval"

# Run evaluation
python tools/run_evaluation.py
```

The loader understands the official dataset format (`dataset.jsonl`: `ID` / `Prompt` / `Insecure_code`). Each line
produces two samples: the insecure completion (positive — measures detection rate) and the benign prompt starter
(negative — measures the false positive rate).

### Measured Result (SecurityEval, full official dataset)

Run against the full official `dataset.jsonl` (121 CWE-annotated samples + 121 benign prompts):

| Metric | Value |
|------|------|
| detection_rate | 81.8% (99/121 insecure samples flagged) |
| false_positive_rate | 0.0% (0/121 benign prompts flagged) |
| avg_latency_ms | 1.28 |

Honest reading: the 0% false-positive rate is the result of lexical stripping (comments/docstrings/strings never
trigger rules) plus taint sanitizers (html.escape, shlex.quote, safe coercion kill the taint flow). The 81.8%
detection rate has grown from the 38.0% baseline via taint-engine expansion (Attribute/Subscript propagation,
new sinks) and new rules; the remaining ~20 misses are CWEs requiring interprocedural dataflow or semantic
reasoning (SSRF via function parameters, missing-auth logic, off-by-one) — exactly what the `sast` orchestrator
delegates to semgrep/CodeQL. The `missed_by_cwe` tally is the direct input for adding new
rules (`tools/mine_cwe_rules.py`) or routing CWEs to the semgrep layer.

### Generic Annotated Corpora (can run even without SecurityEval)

`run_evaluation.py --corpus` accepts any JSONL (each line `{code, insecure, cwe}`) or a source directory:

```bash
python tools/run_evaluation.py --corpus tests/sample_corpus.jsonl   # built-in sample
python tools/run_evaluation.py --corpus D:/datasets/your_data.jsonl # any annotated data
```

Metric definitions are consistent with SecurityEval (detection_rate / false_positive_rate / avg_latency_ms / missed_by_cwe).

### Metric Description

| Metric | Meaning | Target |
|------|------|------|
| `detection_rate` | Detection rate on malicious samples | Higher is better (baseline reference >0.7) |
| `false_positive_rate` | False positive rate on safe samples | Lower is better (<0.05) |
| `repair_success_rate` | Convergence rate of the repair loop within 3 rounds | Higher is better |
| `avg_repair_rounds` | Average number of repair rounds | Lower is better |
| `avg_latency_ms` | Average validation latency | <50ms |

### Missed Detection Analysis

The `missed_by_cwe` field in the evaluation report tallies missed detections by CWE — this is the **direct basis for
rule iteration**: for the CWEs with the most missed detections, add matching patterns to `rules/*.yaml` (you can use
`tools/mine_cwe_rules.py` to mine fixes from the GHSA-CySec dataset), then rerun the evaluation to verify improvement.

### Integration with GHSA-CySec (rule expansion loop)

```bash
# 1. Apply for and download GHSA-CySec from ModelScope (reachable within China)
modelscope download --dataset couvor/GHSA-CySec --local_dir D:\datasets\GHSA-CySec

# 2. Mine CWE → fixes → automatically append rules/cwe_reference.yaml
python tools/mine_cwe_rules.py D:\datasets\GHSA-CySec

# 3. Add detection patterns to rules/*.yaml based on the new knowledge → rerun evaluation
```

## Local Log Mining (offline, the loop is fully available)

No external dataset needed: mine rule candidates directly from runtime missed-detection records (promoted to official
rules after human review):

```bash
# Report a missed pattern (when the Agent finds a pattern the validator did not catch)
python cli.py missed --pattern 'getattr(builtins, "eval")(x)' --note "dynamic builtins access bypass"

# Mine missed patterns → generate review checklist logs/pending_rules.json
python tools/mine_cwe_rules.py --from-logs
```

> Proven in practice: the `getattr(builtins, "eval")` bypass discovered via log mining has been promoted to rule BL-005
> and added to regression tests — this is the minimum viable path of the "reward loop" (find attack → record →
> automatically find a fix → update rules).

## Full Picture of the Iteration Loop

```
missed detections in evaluation (missed_by_cwe) ──┐
manual modification diff (logs) ──────────────────┼─► human review ─► new rules/*.yaml rules ─► rerun evaluation to verify
Agent missed-pattern reports (missed) ────────────┘          (anti-poisoning gate)        │
        ▲                                                                                 │
        └────────────────── continuous loop ◄─────────────────────────────────────────────┘
```
