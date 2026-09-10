"""core/taint_ml.py — Cross-statement taint-lite for js/java (multi-language AST plan, phase 3).

Design: a statement-ordered flat taint map per function scope, built from the
tree-sitter AST (core/xast). For every direct statement of a function body we

  1. update the map: `x = <expr>` taints x when <expr> contains a source or
     an already-tainted variable; a sanitizer call kills the taint; any other
     assignment overwrites (and clears) it;
  2. scan for sinks: a call whose argument (or constructor argument) contains
     a source or a tainted variable emits a finding with its provenance chain.

Language tables:

  sources  js  : req.query/body/params/cookies, process.argv, location.*
           java: *request.getParameter/getParameterValues/getHeader
  sinks    js  : child_process exec/execSync, res.send/end/write (XSS),
                 res.redirect (open redirect), fs.* file ops (path traversal),
                 *.query/execute (SQL)
           java: Runtime.getRuntime().exec, new ProcessBuilder (command inj.),
                 *.executeQuery/executeUpdate/execute (SQL)
  sanitizers js : encodeURIComponent, escapeHtml, sanitizeHtml, ...
             java: escapeHtml/escapeHtml4, Jsoup.clean, ...

Scope rules (conservative by design — the 0% false-positive red line):
  - each FUNCTION body is its own taint scope; module-level (js) / root and
    class-body (java) statements form their own scopes;
  - nested function bodies are processed independently with their own maps;
  - control-flow blocks share the enclosing scope's map (block-scoped
    identifier shadowing is a rare accepted edge);
  - no inter-procedural or object-field tracking, destructuring is ignored.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from core import xast

_JS_FUNC_TYPES = ("function_declaration", "function_expression",
                  "method_definition", "arrow_function")
_JAVA_FUNC_TYPES = ("method_declaration", "constructor_declaration")

# node types whose bodies are opaque to taint traversal (shadowing scopes)
_OPAQUE = {
    "function_declaration", "function_expression", "method_definition",
    "arrow_function", "class_declaration", "class_body", "decorated_definition",
    "method_declaration", "constructor_declaration", "interface_declaration",
    "lambda_expression", "anonymous_class",
}

# node types that can declare/assign a variable in one statement
_JS_ASSIGN_TYPES = ("variable_declarator", "assignment_expression")
_JAVA_ASSIGN_TYPES = ("variable_declarator", "assignment_expression")

JS_SANITIZERS = {
    "encodeURI", "encodeURIComponent", "escapeHtml", "escapeHTML",
    "sanitizeHtml", "sanitize", "DOMPurify.sanitize",
}
JAVA_SANITIZERS = {
    "escapeHtml", "escapeHtml4", "stripXSS", "clean", "sanitize", "Jsoup.clean",
}

# js sinks: (call name, rule_id, allowed object prefixes, bare allowed)
_JS_SINKS: list[tuple[str, str, tuple[str, ...], bool]] = [
    ("exec", "JS-006", ("child_process",), True),
    ("execSync", "JS-006", ("child_process",), True),
    ("send", "JS-007", ("res",), False),
    ("end", "JS-007", ("res",), False),
    ("write", "JS-007", ("res",), False),
    ("redirect", "JS-015", ("res",), False),
    ("readFile", "JS-016", ("fs", "fs/promises"), False),
    ("readFileSync", "JS-016", ("fs", "fs/promises"), False),
    ("writeFile", "JS-016", ("fs", "fs/promises"), False),
    ("writeFileSync", "JS-016", ("fs", "fs/promises"), False),
    ("createReadStream", "JS-016", ("fs", "fs/promises"), False),
    ("createWriteStream", "JS-016", ("fs", "fs/promises"), False),
    ("unlink", "JS-016", ("fs", "fs/promises"), False),
    ("unlinkSync", "JS-016", ("fs", "fs/promises"), False),
    ("appendFile", "JS-016", ("fs", "fs/promises"), False),
    ("query", "JS-010", (), True),
    ("execute", "JS-010", (), True),
]

_JAVA_SINKS: list[tuple[str, str, tuple[str, ...], bool]] = [
    ("executeQuery", "JAVA-002", (), True),
    ("executeUpdate", "JAVA-002", (), True),
]


def _text(node: Any) -> str:
    try:
        return node.text.decode("utf-8", "replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# source / sanitizer matching
# ---------------------------------------------------------------------------

_JS_SOURCE_SEGMENTS = ("query", "body", "params", "cookies")
_LOCATION_RE = re.compile(r"(window\.|document\.)?location\.(search|hash|href|pathname)")
_JAVA_REQ_RE = re.compile(r"\w*req\w*", re.IGNORECASE)
_JAVA_SOURCE_NAMES = {"getParameter", "getParameterValues", "getHeader"}


def _js_source_text(txt: str) -> Optional[str]:
    """Return a source description when a member-expression text is a JS source."""
    if txt.startswith("process.argv"):
        rest = txt[len("process.argv"):]
        if rest == "" or rest[0] == "[":
            return "process.argv"
        return None
    if txt.startswith("req."):
        rest = txt[len("req."):]
        for seg in _JS_SOURCE_SEGMENTS:
            if rest.startswith(seg):
                tail = rest[len(seg):]
                if tail == "" or tail[0] in ".[":
                    return f"req.{seg}"
        return None
    if _LOCATION_RE.match(txt):
        return "location"
    return None


def _java_source_name(node: Any) -> Optional[str]:
    """Return a source description when a method_invocation is a servlet source."""
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return None
    name = _text(name_node)
    if name.split(".")[-1] not in _JAVA_SOURCE_NAMES:
        return None
    obj = node.child_by_field_name("object")
    if obj is None:
        return None
    last = _text(obj).strip().split(".")[-1]
    if not _JAVA_REQ_RE.fullmatch(last):
        return None
    return f"request.{name}"


def _sanitized(value: Any, language: str) -> bool:
    """True when the value is a call to a known sanitizer."""
    sanitizers = JS_SANITIZERS if language == "js" else JAVA_SANITIZERS
    if language == "js":
        if value.type != "call_expression":
            return False
        name = _js_call_name(value)
    else:
        if value.type != "method_invocation":
            return False
        name_node = value.child_by_field_name("name")
        name = _text(name_node) if name_node is not None else ""
    return name.split(".")[-1] in sanitizers


def _js_call_name(node: Any) -> str:
    name = _text(_js_fn(node))
    return name


def _js_fn(node: Any) -> Any:
    return node.child_by_field_name("function")


# ---------------------------------------------------------------------------
# taint containment / propagation
# ---------------------------------------------------------------------------

def _contains_taint(node: Any, language: str, taint_map: dict[str, str]) -> Optional[str]:
    """Return the taint chain when the node contains a source or tainted var."""
    if node is None:
        return None
    kind = node.type
    if kind in _OPAQUE:
        return None
    if kind == "identifier":
        return taint_map.get(_text(node))
    if language == "js" and kind == "member_expression":
        src = _js_source_text(_text(node))
        if src:
            return src
    if language == "java" and kind == "method_invocation":
        src = _java_source_name(node)
        if src:
            return src
    for child in node.named_children:
        chain = _contains_taint(child, language, taint_map)
        if chain:
            return chain
    return None


def _assignment_target(node: Any) -> Optional[str]:
    """Extract the assigned identifier name from an assignment node."""
    if node.type == "variable_declarator":
        name_node = node.child_by_field_name("name")
        if name_node is not None and name_node.type == "identifier":
            return _text(name_node)
        return None
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        if left is not None and left.type == "identifier":
            return _text(left)
        return None
    return None


def _assignment_value(node: Any) -> Any:
    if node.type == "variable_declarator":
        return node.child_by_field_name("value")
    if node.type == "assignment_expression":
        return node.child_by_field_name("right")
    return None


def _walk(node: Any):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for c in n.named_children:
            stack.append(c)


# ---------------------------------------------------------------------------
# sinks
# ---------------------------------------------------------------------------

def _sink_matches(name: str, call: str, prefixes: tuple[str, ...], bare: bool) -> Optional[str]:
    """Return the object base when name is a sink call, else None.

    None  = not this sink (continue scanning)
    ""    = matched as a bare call
    "res" = matched as res.send / child_process.exec / ...
    """
    if "." not in name:
        if bare and name == call:
            return ""
        return None
    if not name.endswith("." + call):
        return None
    base = name[: -(len(call) + 1)]
    if not prefixes:  # any prefixed caller accepted
        return base
    return base if base in prefixes else None


def _scan_js_sinks(stmt: Any, taint_map: dict[str, str], findings: list[dict[str, Any]]) -> None:
    for node in _walk(stmt):
        if node.type != "call_expression":
            continue
        fn_node = _js_fn(node)
        if fn_node is None:
            continue
        name = xast._js_call_name(node)
        if not name:
            continue
        for call, rule_id, prefixes, bare in _JS_SINKS:
            base = _sink_matches(name, call, prefixes, bare)
            if base is None:
                continue
            args_node = node.child_by_field_name("arguments")
            named = list(args_node.named_children) if args_node is not None else []
            chains = [c for a in named if (c := _contains_taint(a, "js", taint_map))]
            if chains:
                findings.append({
                    "rule_id": rule_id,
                    "line": node.start_point[0] + 1,
                    "col": node.start_point[1],
                    "chain": f"{chains[0]} → {name}",
                })
                break  # one finding per call expression


def _scan_java_sinks(stmt: Any, taint_map: dict[str, str], findings: list[dict[str, Any]]) -> None:
    for node in _walk(stmt):
        kind = node.type
        if kind == "method_invocation":
            name = _java_invocation_name(node)
            if not name:
                continue
            # Runtime.getRuntime().exec(...)
            if name.endswith(".exec") and "getRuntime" in name:
                args_node = node.child_by_field_name("arguments")
                named = list(args_node.named_children) if args_node is not None else []
                chains = [c for a in named if (c := _contains_taint(a, "java", taint_map))]
                if chains:
                    findings.append({
                        "rule_id": "JAVA-001",
                        "line": node.start_point[0] + 1,
                        "col": node.start_point[1],
                        "chain": f"{chains[0]} → {name}",
                    })
                continue
            for call, rule_id, prefixes, bare in _JAVA_SINKS:
                if name != call and not name.endswith(f".{call}"):
                    continue
                args_node = node.child_by_field_name("arguments")
                named = list(args_node.named_children) if args_node is not None else []
                chains = [c for a in named if (c := _contains_taint(a, "java", taint_map))]
                if chains:
                    findings.append({
                        "rule_id": rule_id,
                        "line": node.start_point[0] + 1,
                        "col": node.start_point[1],
                        "chain": f"{chains[0]} → {name}",
                    })
                    break
        elif kind == "object_creation_expression":
            type_node = node.child_by_field_name("type")
            if type_node is not None and _text(type_node) == "ProcessBuilder":
                args_node = node.child_by_field_name("arguments")
                named = list(args_node.named_children) if args_node is not None else []
                chains = [c for a in named if (c := _contains_taint(a, "java", taint_map))]
                if chains:
                    findings.append({
                        "rule_id": "JAVA-001",
                        "line": node.start_point[0] + 1,
                        "col": node.start_point[1],
                        "chain": f"{chains[0]} → new ProcessBuilder",
                    })


def _java_invocation_name(node: Any) -> str:
    """Dotted invocation name, e.g. Runtime.getRuntime.exec (parens dropped)."""
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return ""
    name = _text(name_node)
    obj = node.child_by_field_name("object")
    if obj is None:
        return name
    if obj.type == "identifier":
        return f"{_text(obj)}.{name}"
    if obj.type == "method_invocation":
        inner = _java_invocation_name(obj)
        return f"{inner}.{name}" if inner else name
    if obj.type == "field_access":
        last = _text(obj).strip().split(".")[-1]
        return f"{last}.{name}" if last else name
    return name


# ---------------------------------------------------------------------------
# scope processing
# ---------------------------------------------------------------------------

def _assign_types(language: str) -> tuple[str, ...]:
    return _JS_ASSIGN_TYPES if language == "js" else _JAVA_ASSIGN_TYPES


def _do_assignments(stmt: Any, language: str, taint_map: dict[str, str]) -> None:
    assign_types = _assign_types(language)
    for node in _walk(stmt):
        if node.type not in assign_types:
            continue
        target = _assignment_target(node)
        if not target:
            continue
        value = _assignment_value(node)
        if value is None:
            continue
        if _sanitized(value, language):
            taint_map.pop(target, None)
            continue
        chain = _contains_taint(value, language, taint_map)
        if chain is None:
            taint_map.pop(target, None)
        else:
            taint_map[target] = f"{chain} → {target}"


def _process_scope(stmts: list[Any], language: str, findings: list[dict[str, Any]]) -> None:
    taint_map: dict[str, str] = {}
    for stmt in stmts:
        _do_assignments(stmt, language, taint_map)
        if language == "js":
            _scan_js_sinks(stmt, taint_map, findings)
        else:
            _scan_java_sinks(stmt, taint_map, findings)


def _collect_functions(node: Any, func_types: tuple[str, ...]):
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in func_types:
            yield n
        for c in n.named_children:
            stack.append(c)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def analyze(code: str, language: str) -> list[dict[str, Any]]:
    """Cross-statement taint findings for js/java.

    Returns [] when tree-sitter/the grammar is unavailable or the code does
    not parse — callers keep the regex baseline, never an error.
    """
    root = xast.parse(code, language)
    if root is None:
        return []
    findings: list[dict[str, Any]] = []

    if language == "js":
        # module-level statements (functions are processed separately below)
        scope_stmts = [
            c for c in root.named_children
            if c.type not in _JS_FUNC_TYPES and c.type != "class_declaration"
        ]
        _process_scope(scope_stmts, "js", findings)
    else:
        # java: standalone snippets at root level + class-body statements
        # (fields/initializers); method bodies are processed below
        scope_stmts = [
            c for c in root.named_children
            if c.type not in ("class_declaration", "interface_declaration",
                              "method_declaration", "constructor_declaration",
                              "import_declaration", "package_declaration")
        ]
        _process_scope(scope_stmts, "java", findings)
        for cls in (c for c in root.named_children if c.type == "class_declaration"):
            body = cls.child_by_field_name("body")
            if body is not None and body.type == "class_body":
                class_stmts = [
                    c for c in body.named_children
                    if c.type not in ("method_declaration", "constructor_declaration",
                                      "class_declaration", "interface_declaration",
                                      "static_initializer")
                ]
                _process_scope(class_stmts, "java", findings)

    func_types = _JS_FUNC_TYPES if language == "js" else _JAVA_FUNC_TYPES
    for fnode in _collect_functions(root, func_types):
        body = fnode.child_by_field_name("body")
        if body is None:
            continue
        # tree-sitter-javascript uses statement_block, java/python use block
        stmts = list(body.named_children) if body.type in ("block", "statement_block") else []
        if stmts:
            _process_scope(stmts, language, findings)

    # dedupe: one finding per (rule_id, line)
    seen: set[tuple[str, int]] = set()
    uniq: list[dict[str, Any]] = []
    for f in findings:
        key = (f["rule_id"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq
