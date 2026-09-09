"""tests/test_xast.py — optional tree-sitter engine (js/java) + degradation tests."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import xast  # noqa: E402
from core.validator import Validator  # noqa: E402

pytest.importorskip("tree_sitter", reason="tree-sitter optional; xast tests skip without it")


def test_xast_available():
    assert xast.xast_available()
    assert xast.load_error() == ""


def test_js_eval_detected_via_xast():
    v = Validator(language="js")
    r = v.validate("eval(userInput);")
    assert not r.passed
    hit = [x for x in r.violations if x.rule_id == "JS-001"]
    assert hit and hit[0].checker == "xast"


def test_js_comment_and_string_immunity():
    v = Validator(language="js")
    assert v.validate("// eval(userInput);").passed
    assert v.validate('const s = "eval(userInput)";').passed


def test_js_string_timer_shapes():
    v = Validator(language="js")
    r1 = v.validate('setTimeout("alert(1)", 100);')
    assert any(x.rule_id == "JS-004" and x.checker == "xast" for x in r1.violations)
    r2 = v.validate("setTimeout(fn, 100);")
    assert not any(x.rule_id == "JS-004" for x in r2.violations)
    r3 = v.validate('setInterval("tick()", 500);')
    assert any(x.rule_id == "JS-004" for x in r3.violations)


def test_js_require_dynamic_arg():
    v = Validator(language="js")
    assert any(x.rule_id == "JS-009" for x in v.validate("require(userPath);").violations)
    assert v.validate("require('fs');").passed
    assert any(x.rule_id == "JS-009" for x in v.validate("const m = require(`./${name}`);").violations)


def test_js_new_function_call_match():
    v = Validator(language="js")
    assert any(x.rule_id == "JS-001" for x in v.validate("new Function(userCode);").violations)


def test_js_safe_template_stays_clean():
    v = Validator(language="js")
    tpl = Path(__file__).resolve().parent.parent / "templates" / "js" / "safe_js_dom.js"
    r = v.validate(tpl.read_text(encoding="utf-8"))
    assert r.passed, r.summary()


def test_java_without_grammar_degrades_to_regex():
    v = Validator(language="java")
    code = 'MessageDigest md = MessageDigest.getInstance("MD5");'
    r = v.validate(code)
    assert not r.passed
    assert all(x.checker != "xast" for x in r.violations)


def test_degradation_regex_still_covers(monkeypatch):
    monkeypatch.setattr(xast, "_supported_languages", lambda: {})
    v = Validator(language="js")
    r = v.validate("eval(userInput);")
    assert not r.passed
    hit = [x for x in r.violations if x.rule_id == "JS-001"]
    assert hit and hit[0].checker == "regex"


def test_call_match_semantics():
    assert xast.call_matches("setTimeout", "setTimeout")
    assert xast.call_matches("setTimeout", "window.setTimeout")
    assert xast.call_matches("Function", "new Function")
    assert xast.call_matches("Function", "Function")
    assert not xast.call_matches("eval", "myEval")
    assert not xast.call_matches("", "eval")


def test_arg_match_semantics():
    assert xast.arg_matches("string", "string-literal")
    assert xast.arg_matches("template", "string-literal")
    assert not xast.arg_matches("dynamic", "string-literal")
    assert xast.arg_matches("template-subst", "dynamic")
    assert xast.arg_matches("concat", "template-subst")
    assert xast.arg_matches("dynamic", "any")
    assert xast.arg_matches("dynamic", "")
