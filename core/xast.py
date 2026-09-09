"""core/xast.py — Optional tree-sitter AST engine for js/java.

Phase 2 of the multi-language AST plan: when tree-sitter (+ per-language
grammars) is installed, js/java rules can use precise AST call matching
(`match.xast`); when absent, everything degrades to the regex engine —
the engine is additive, never a hard dependency (same treatment as semgrep).

Status contract (mirrors the semgrep delegation in core/sast.py):
  - xast_available() -> bool      # grammars importable; cheap and cached
  - unparsable code -> empty result, never an error
  - languages without a grammar (java today) return no calls — regex rules
    still cover them; the grammar lands with phase 3.

Call matching semantics mirror the python AST engine (core/validator.py
_check_ast): full dot-path match or bare-name tail match.
"""
from __future__ import annotations

import importlib
from typing import Any

# language -> grammar module (js ships with phase 2; java arrives with phase 3)
_GRAMMARS: dict[str, str] = {
    "js": "tree_sitter_javascript",
    "java": "tree_sitter_java",
}

_langs: dict[str, Any] = {}
_load_error: str = ""


def _supported_languages() -> dict[str, Any]:
    """Import tree-sitter + grammars once; returns {lang: Language}."""
    global _load_error
    if _langs:
        return _langs
    try:
        import tree_sitter
    except ImportError:
        _load_error = "tree-sitter not installed"
        return {}
    for lang, mod in _GRAMMARS.items():
        try:
            m = importlib.import_module(mod)
            _langs[lang] = tree_sitter.Language(m.language())
        except ImportError:
            _load_error = f"{mod} not installed"
        except Exception as exc:  # grammar/version mismatch
            _load_error = f"{mod}: {exc}"
    return _langs


def xast_available() -> bool:
    """True when tree-sitter + at least one grammar is importable."""
    return bool(_supported_languages())


def load_error() -> str:
    """Reason xast is unavailable ("" when available)."""
    _supported_languages()
    return _load_error


# ---------------------------------------------------------------------------
# call extraction
# ---------------------------------------------------------------------------

def _js_call_name(node: Any) -> str:
    """Reduce a call target to a dot-path: identifier / member_expression."""
    fn = node.child_by_field_name("function")
    if fn is None:
        return ""
    kind = fn.type
    if kind == "identifier":
        return _text(fn)
    if kind == "member_expression":
        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        base = ""
        if obj is not None and obj.type in ("identifier", "member_expression"):
            base = _text(obj)
        prop_name = _text(prop) if prop is not None else ""
        if base and prop_name:
            return f"{base}.{prop_name}"
        return prop_name or base
    return ""


def _text(node: Any) -> str:
    try:
        return node.text.decode("utf-8", "replace")
    except Exception:
        return ""


def _arg_shape(node: Any) -> str:
    """Classify one argument expression for the xast arg constraint.

    Shapes: string | template | template-subst | concat | dynamic
    """
    kind = node.type
    if kind == "string":
        return "string"
    if kind == "template_string":
        has_subst = any(c.type == "template_substitution" for c in node.named_children)
        return "template-subst" if has_subst else "template"
    if kind == "binary_expression":
        op = node.child_by_field_name("operator")
        if op is not None and _text(op) == "+":
            return "concat"
        return "dynamic"
    if kind in ("identifier", "member_expression", "call_expression",
                "await_expression", "parenthesized_expression"):
        return "dynamic"
    # number / true / false / null / object / arrow_function / regex ...
    return "dynamic"


def _collect_js_calls(root: Any) -> list[dict[str, Any]]:
    """Walk a JS tree; returns call/new-expression infos with arg shapes."""
    out: list[dict[str, Any]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in ("call_expression", "new_expression"):
            if node.type == "call_expression":
                name = _js_call_name(node)
            else:
                ctor = node.child_by_field_name("constructor")
                name = ("new " + _text(ctor)) if ctor is not None else ""
            args_node = node.child_by_field_name("arguments")
            named = list(args_node.named_children) if args_node is not None else []
            if name:
                out.append({
                    "name": name,
                    "line": node.start_point[0] + 1,
                    "col": node.start_point[1],
                    "shapes": [_arg_shape(a) for a in named],
                })
        for child in node.children:
            stack.append(child)
    return out


def analyze_calls(code: str, language: str) -> list[dict[str, Any]]:
    """Extract call infos for a language.

    Returns [] when tree-sitter/the grammar is unavailable or the code does
    not parse — callers fall back to the regex engine, never an error.
    """
    langs = _supported_languages()
    if language == "js" and "js" in langs:
        from tree_sitter import Parser
        try:
            parser = Parser(langs["js"])
            tree = parser.parse(code.encode("utf-8"))
        except Exception:
            return []
        return _collect_js_calls(tree.root_node)
    return []  # java/other: no grammar wired yet (phase 3)


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------

def call_matches(target: str, full: str) -> bool:
    """AST-engine call semantics (mirrors _check_ast): full-path or tail match.

    target "setTimeout" hits setTimeout and window.setTimeout;
    target "Function" hits new Function and Function (bare call).
    """
    if not target or not full:
        return False
    if full == target:
        return True
    if full.startswith("new "):
        stripped = full[4:]
        if stripped == target or stripped.split(".")[-1] == target:
            return True
    return full.split(".")[-1] == target


def arg_matches(shape: str, expected: str) -> bool:
    """Check one argument shape against the rule's xast arg constraint.

    expected values:
      "string-literal" -> plain string or template without substitutions
      "template-subst" -> template with ${...} or binary + concatenation
      "dynamic"        -> anything that is not a plain literal
      "any"            -> always
    """
    if expected in ("", "any"):
        return True
    if expected == "string-literal":
        return shape in ("string", "template")
    if expected == "template-subst":
        return shape in ("template-subst", "concat")
    if expected == "dynamic":
        return shape in ("dynamic", "template-subst", "concat")
    return False
