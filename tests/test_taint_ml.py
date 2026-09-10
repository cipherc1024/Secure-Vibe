"""tests/test_taint_ml.py — js/java cross-statement taint-lite (phase 3) tests."""
# secure-vibe: ignore-file - deliberate attack samples as test fixtures
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import taint_ml, xast  # noqa: E402
from core.validator import Validator  # noqa: E402

pytest.importorskip("tree_sitter", reason="tree-sitter optional; taint_ml tests skip without it")

REPO = Path(__file__).resolve().parent.parent

# --- js cross-statement flows ---------------------------------------------------


def test_js_redirect_cross_statement():
    v = Validator(language="js")
    code = "const id = req.query.id;\nres.redirect('/p?id=' + id);"
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JS-015" and x.checker == "taint"]
    assert hit, [(x.rule_id, x.checker) for x in r.violations]
    assert "req.query" in hit[0].message and "id" in hit[0].message


def test_js_fs_traversal_in_function():
    v = Validator(language="js")
    code = "function f() {\n  const p = req.params.path;\n  fs.readFile(p, cb);\n}"
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JS-016" and x.checker == "taint"]
    assert hit, r.summary()


def test_js_sql_var_cross_line():
    v = Validator(language="js")
    code = "const q = 'SELECT * FROM t WHERE id=' + req.query.id;\ndb.query(q, cb);"
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JS-010" and x.checker == "taint"]
    assert hit, [(x.rule_id, x.checker) for x in r.violations]


def test_js_xss_res_send_cross_line():
    v = Validator(language="js")
    code = "const msg = req.body.msg;\nres.send(msg);"
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JS-007" and x.checker == "taint"]
    assert hit, [(x.rule_id, x.checker) for x in r.violations]


def test_js_exec_with_argv():
    v = Validator(language="js")
    code = "const { exec } = require('child_process');\nconst target = process.argv[2];\nexec('ping ' + target);"
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JS-006" and x.checker == "taint"]
    assert hit, [(x.rule_id, x.checker) for x in r.violations]


# --- js benign / scope correctness ----------------------------------------------


def test_js_benign_locals_pass():
    v = Validator(language="js")
    code = "const params = new URLSearchParams(location.search);\nconst q = params.get('q');\nres.json({ q });"
    r = v.validate(code)
    assert not any(x.checker == "taint" for x in r.violations)


def test_js_constant_and_reassignment_pass():
    v = Validator(language="js")
    code = "let id = req.query.id;\nid = 42;\nres.send(id);"
    r = v.validate(code)
    assert not any(x.rule_id == "JS-007" and x.checker == "taint" for x in r.violations)


def test_js_sanitizer_kills_taint():
    v = Validator(language="js")
    code = "const q = escapeHtml(req.query.q);\nres.send(q);"
    r = v.validate(code)
    assert not any(x.rule_id == "JS-007" and x.checker == "taint" for x in r.violations)


def test_js_function_scopes_isolated():
    v = Validator(language="js")
    code = (
        "function one() {\n  const id = req.query.id;\n  res.redirect(id);\n}\n"
        "function two() {\n  const id = 42;\n  res.redirect('/x');\n  res.send(id);\n}"
    )
    r = v.validate(code)
    taints = [(x.rule_id, x.line) for x in r.violations if x.checker == "taint"]
    assert (("JS-015", 3)) in taints, taints
    assert all(rule != "JS-007" for rule, _ in taints)


def test_js_same_line_regex_upgraded_to_taint():
    v = Validator(language="js")
    r = v.validate("res.redirect(req.query.url);")
    hits = [x for x in r.violations if x.rule_id == "JS-015"]
    assert len(hits) == 1 and hits[0].checker == "taint"


# --- java cross-statement flows -------------------------------------------------


def test_java_exec_cross_statement():
    v = Validator(language="java")
    code = 'String cmd = request.getParameter("cmd");\nRuntime.getRuntime().exec("sh -c " + cmd);'
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JAVA-001" and x.checker == "taint"]
    assert hit, [(x.rule_id, x.checker) for x in r.violations]


def test_java_processbuilder_arg():
    v = Validator(language="java")
    code = 'String c = req.getParameter("c");\nProcessBuilder pb = new ProcessBuilder(c);'
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JAVA-001" and x.checker == "taint"]
    assert hit, [(x.rule_id, x.checker) for x in r.violations]


def test_java_jdbc_var_cross_line():
    v = Validator(language="java")
    code = (
        'String id = request.getHeader("x");\n'
        'String sql = "SELECT * FROM users WHERE id=" + id;\n'
        "Statement st = conn.createStatement();\n"
        "ResultSet rs = st.executeQuery(sql);"
    )
    r = v.validate(code)
    hit = [x for x in r.violations if x.rule_id == "JAVA-002" and x.checker == "taint"]
    assert hit, [(x.rule_id, x.checker) for x in r.violations]


def test_java_prepared_statement_clean():
    v = Validator(language="java")
    code = (
        'String sql = "SELECT * FROM users WHERE id = ?";\n'
        "PreparedStatement ps = conn.prepareStatement(sql);\n"
        "ps.setString(1, username);\n"
        "ResultSet rs = ps.executeQuery();"
    )
    r = v.validate(code)
    assert not any(x.checker == "taint" for x in r.violations)


def test_java_benign_pass():
    v = Validator(language="java")
    code = 'String name = "world";\nSystem.out.println("hello " + name);'
    r = v.validate(code)
    assert not any(x.checker == "taint" for x in r.violations)


# --- templates stay clean --------------------------------------------------------


def test_safe_templates_clean_with_taint():
    for rel, lang in (("js/safe_js_dom.js", "js"), ("java/safe_java_db.java", "java")):
        code = (REPO / "templates" / rel).read_text(encoding="utf-8")
        v = Validator(language=lang)
        r = v.validate(code)
        assert r.passed, (rel, [(x.rule_id, x.line) for x in r.violations])


# --- degradation -----------------------------------------------------------------


def test_taint_ml_analyze_degrades_when_no_grammar(monkeypatch):
    monkeypatch.setattr(xast, "_supported_languages", lambda: {})
    v = Validator(language="js")
    code = "const id = req.query.id;\nres.redirect('/x?id=' + id);"
    r = v.validate(code)
    assert not any(x.checker == "taint" for x in r.violations)

    raw = taint_ml.analyze("const id = req.query.id;", "js")
    assert raw == []


def test_taint_ml_analyze_direct_findings():
    out = taint_ml.analyze("const id = req.query.id;\nres.send(id);", "js")
    assert any(f["rule_id"] == "JS-007" and "req.query" in f["chain"] for f in out)
