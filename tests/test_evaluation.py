"""tests/test_evaluation.py - SecurityEval loader (official dataset format)."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from run_evaluation import load_securityeval_samples, evaluate  # noqa: E402


def _write(tmp_path, lines):
    p = tmp_path / "dataset.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_official_format_two_samples_per_line(tmp_path):
    line = json.dumps({
        "ID": "CWE-020_author_1.py",
        "Prompt": "import yaml\n\ndef yaml_load(filename):\n    '''docstring'''\n    return filename",
        "Insecure_code": "import yaml\n\ndef yaml_load(filename):\n    with open(filename) as f:\n        return yaml.load(f, Loader=yaml.BaseLoader)",
    })
    p = _write(tmp_path, [line])
    samples = load_securityeval_samples(p)
    assert len(samples) == 2
    flags = {s["insecure"] for s in samples}
    assert flags == {True, False}
    assert all(s["cwe"] == "CWE-020" for s in samples)


def test_official_format_empty_fields_skipped(tmp_path):
    line = json.dumps({"ID": "CWE-798_x.py", "Prompt": "", "Insecure_code": "API_KEY = 'sk-live-abcdef1234567890'"})
    p = _write(tmp_path, [line])
    samples = load_securityeval_samples(p)
    assert len(samples) == 1
    assert samples[0]["insecure"] is True


def test_generic_format_still_supported(tmp_path):
    line = json.dumps({"code": "eval(user_input)", "insecure": True, "cwe": "CWE-095"})
    p = _write(tmp_path, [line])
    samples = load_securityeval_samples(p)
    assert len(samples) == 1
    assert samples[0]["insecure"] is True
    assert samples[0]["cwe"] == "CWE-095"


def test_evaluate_runs_on_official_samples(tmp_path):
    line = json.dumps({
        "ID": "CWE-798_author_1.py",
        "Prompt": "API_KEY = 'placeholder'\n\n\ndef connect():\n    pass",
        "Insecure_code": "API_KEY = 'sk-live-abcdef1234567890'\n\n\ndef connect():\n    return API_KEY",
    })
    p = _write(tmp_path, [line])
    samples = load_securityeval_samples(p)
    report = evaluate(samples)
    assert report["total_samples"] == 2
    assert report["insecure_samples"] == 1
    assert report["safe_samples"] == 1
