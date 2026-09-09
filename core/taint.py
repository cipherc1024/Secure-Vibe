"""taint.py — Lightweight taint analysis (AST level).

Adds data-flow confirmation on top of dangerous-function matching: when a dangerous
sink's arguments actually originate from user input (a taint source), report a
higher-confidence violation (checker=taint).

Design trade-offs (lightweight; sanitizers are deliberately not modeled):
  - sound over-approx: once a variable is assigned tainted values it stays tainted (sanitize is not modeled)
  - only the "confirmed taint + dangerous sink" combination is reported, used to:
      1. upgrade repair advice (carries the taint chain so the LLM can fix precisely)
      2. detect injection through variable indirection (cmd = input(); os.system(cmd))
      3. compute a "confirmed injection" metric in later evaluations

Taint sources: input() / raw_input() / sys.argv / sys.stdin / request.* / socket.recv*
Propagation:  assignment / BinOp concatenation / f-string / % formatting / .format / .join / argument pass-through
Sinks:  os.system|popen -> PY-002; eval|exec -> PY-001;
        subprocess.*(shell=True) -> PY-003; pickle.load(s) (incl. cPickle/_pickle) -> PY-004;
        yaml.load -> PY-005; "execute" with SQL concatenation -> GEN-005 (drives LLM repair advice)
Extended sinks (SecurityEval coverage):
        redirect/HttpResponseRedirect -> PY-024; make_response|*.render -> PY-025;
        headers.add/extend(tainted) -> PY-026; logging calls with tainted args -> PY-027;
        re.compile(tainted) -> PY-028; *.xpath(tainted) -> PY-029; *.search*(tainted) -> PY-030;
        *.scan/query(FilterExpression=tainted) -> PY-031; open/send_file(tainted) -> PY-032

Output: list[dict{rule_id, line, col, message, chain, severity}]
"""
from __future__ import annotations

import ast
from typing import Any, Optional

# ---------------------------------------------------------------------------
# node identity helpers
# ---------------------------------------------------------------------------

def _nid(node: ast.AST) -> int:
    return id(node)


# ---------------------------------------------------------------------------
# taint source / sink identification
# ---------------------------------------------------------------------------

def _is_source(node: ast.expr) -> Optional[str]:
    """Return the source description when the node is a taint source, else None."""
    # input() / raw_input()
    if isinstance(node, ast.Call):
        name = _func_name(node.func)
        if name in ("input", "raw_input"):
            return f"{name}()"
        # sys.stdin.read() / sys.stdin.readline() / sys.stdin.readlines()
        if name in ("sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines",
                    "sys.stdin.buffer.read", "sys.stdin.buffer.readline"):
            return name
        # direct request method calls: request.get_data() / request.get_json() / ...
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                and node.func.value.id == "request":
            return f"request.{node.func.attr}(...)"
        # direct request method calls: request.get_data() / request.get_json() / ...
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                and node.func.value.id == "request":
            return f"request.{node.func.attr}(...)"
    # sys.argv / sys.stdin subscript access
    if isinstance(node, ast.Subscript):
        base = node.value
        if (isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name)
                and base.value.id == "sys" and base.attr in ("argv", "stdin")):
            return f"sys.{base.attr}[...]"
        # request subscript access: request.args['x'] / request.form['x'] / request.files['x']
        if isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name) \
                and base.value.id == "request":
            return f"request.{base.attr}[...]"
        # chained subscript: request.args['a']['b']
        if isinstance(base, ast.Subscript):
            inner = _is_source(base)
            if inner:
                return f"{inner}[...]"
    # file-object reads (file.read() where file came from open() — too approximate; explicit sys.stdin only)
    # request.args / request.form / ... (web frameworks)
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return f"request.{node.attr}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        f = node.func
        if (isinstance(f.value, ast.Attribute) and isinstance(f.value.value, ast.Name)
                and f.value.value.id == "request"):
            return f"request.{f.value.attr}.{f.attr}(...)"
    return None


def _func_name(func: ast.expr) -> str:
    """Reduce a function name (os.system / eval / request.args.get ...)."""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _sink_rule(call: ast.Call) -> Optional[str]:
    """Return the matching rule ID when the call is a dangerous sink."""
    name = _func_name(call.func)
    tail = name.split(".")[-1]
    if name in ("eval", "exec"):
        return "PY-001"
    if name in ("os.system", "os.popen"):
        return "PY-002"
    # subprocess family: a command-injection sink only when shell=True
    if tail in ("run", "call", "Popen", "check_output", "check_call") and "subprocess" in name:
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return "PY-003"
        return None
    # pickle family: accept cPickle/_pickle aliases (CWE-502)
    root = name.split(".")[0].lstrip("_").lower()
    if tail in ("loads", "load") and root in ("pickle", "cpickle", "marshal", "dill"):
        return "PY-004"
    if name in ("yaml.load", "yaml.unsafe_load"):
        return "PY-005"
    # --- extended sinks (only reported when arguments are taint-confirmed) ---
    if name == "redirect" or tail == "HttpResponseRedirect":
        return "PY-024"  # open redirect with a user-controlled target
    if name in ("make_response", "flask.make_response") or tail == "render":
        return "PY-025"  # user input written into an HTTP response body
    if tail in ("add", "extend") and "header" in name.lower():
        return "PY-026"  # HTTP response header built from user input
    if ("logging" in name or "logger" in name.lower()) and tail in (
            "error", "info", "warning", "critical", "debug", "exception", "log"):
        return "PY-027"  # log injection via user input
    if name == "re.compile":
        return "PY-028"  # ReDoS via user-controlled regex
    if tail in ("xpath", "findall", "find") and not name.startswith("re."):
        return "PY-029"  # XPath/XML-path injection via user-built queries
    if tail in ("search", "search_s", "search_ext_s", "search_filter"):
        return "PY-030"  # injection through user-built search filters (LDAP etc.)
    if tail in ("scan", "query"):
        for kw in call.keywords:
            if kw.arg in ("FilterExpression", "KeyConditionExpression"):
                return "PY-031"  # NoSQL injection (DynamoDB-style filters)
    if name in ("open", "send_file", "flask.send_file"):
        return "PY-032"  # tainted file access (path traversal / arbitrary read)
    if tail in ("fromstring", "parse") and ("xml" in name.lower() or "etree" in name.lower()):
        return "PY-047"  # tainted XML parsing (XXE / entity expansion)
    if tail in ("save", "saveas"):
        return "PY-048"  # tainted file save (unvalidated upload path)
    return None


def _is_sink_node(node: ast.AST) -> Optional[str]:
    return _sink_rule(node) if isinstance(node, ast.Call) else None


# ---------------------------------------------------------------------------
# propagation: determine whether a node is tainted
# ---------------------------------------------------------------------------

# functions that neutralize untrusted data; taint is killed at these calls
SANITIZERS = {
    "html.escape", "cgi.escape", "markupsafe.escape", "jinja2.escape",
    "shlex.quote", "pipes.quote", "urllib.parse.quote",
    "urllib.parse.quote_plus", "re.escape", "secure_filename",
    "werkzeug.utils.secure_filename",
}
_SANITIZER_TAILS = frozenset(s.split(".")[-1] for s in SANITIZERS)
_SAFE_COERCIONS = frozenset({"int", "float", "bool"})

class _TaintEngine:
    def __init__(self, tree: ast.AST):
        self.tainted: set[int] = set()
        self.origin: dict[int, str] = {}
        self.tree = tree
        self.name_origin: dict[str, str] = {}

    def analyze(self) -> None:
        self._mark_sources()
        # fixpoint iteration: assignment/concat propagation until stable
        changed = True
        while changed:
            changed = False
            self._rebuild_name_map()
            for node in ast.walk(self.tree):
                if _nid(node) in self.tainted:
                    continue
                origin = self._propagate_origin(node)
                if origin:
                    self.tainted.add(_nid(node))
                    self.origin[_nid(node)] = origin
                    changed = True
        self._rebuild_name_map()

    def _mark_sources(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.expr):
                src = _is_source(node)
                if src:
                    self.tainted.add(_nid(node))
                    self.origin[_nid(node)] = src

    def _rebuild_name_map(self) -> None:
        """One pass to prebuild the name->origin map (later O(1) lookups)."""
        self.name_origin = {}
        for n in ast.walk(self.tree):
            if _nid(n) not in self.tainted or not isinstance(n, ast.Assign):
                continue
            o = self.origin.get(_nid(n), "tainted variable")
            for t in n.targets:
                if isinstance(t, ast.Name):
                    self.name_origin.setdefault(t.id, o)

    def _expr_origin(self, node: Optional[ast.AST]) -> Optional[str]:
        """Whether the expression is tainted; return the origin description or None."""
        if node is None:
            return None
        if _nid(node) in self.tainted:
            return self.origin.get(_nid(node), "taint source")
        if isinstance(node, ast.Name):
            return self.name_origin.get(node.id)
        return None

    def _propagate_origin(self, node: ast.AST) -> Optional[str]:
        """Return the origin this node should inherit (first of several), else None."""
        # assignment / augmented assignment: tainted RHS taints the whole assignment
        if isinstance(node, ast.Assign):
            return self._expr_origin(node.value)
        if isinstance(node, ast.AnnAssign):
            return self._expr_origin(node.value) if node.value else None
        if isinstance(node, ast.AugAssign):
            return self._expr_origin(node.value)
        # concatenation-like: tainted if any child is tainted
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
            return self._first_child_origin(node)
        # calls: argument taint passes through (over-approx); sinks handled in find_sinks
        if isinstance(node, ast.Call):
            fn = _func_name(node.func)
            if fn:
                tail = fn.split(".")[-1]
                if fn in SANITIZERS or tail in _SANITIZER_TAILS or tail in _SAFE_COERCIONS:
                    return None  # sanitized: taint is killed at this boundary
            origin = self._first_child_origin(node)
            return origin
        # attribute / subscript access: p.filename / d['key'] inherit taint
        # from their base object (over-approximation)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._expr_origin(node.value)
        return None

    def _first_child_origin(self, node: ast.AST) -> Optional[str]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                o = self._expr_origin(child)
                if o:
                    return o
            # keyword arguments
            if isinstance(child, ast.keyword) and child.value is not None:
                o = self._expr_origin(child.value)
                if o:
                    return o
        return None

    # -- reporting -----------------------------------------------------------

    def find_sinks(self) -> list[dict[str, Any]]:
        """Find dangerous sink calls whose arguments are tainted."""
        findings: list[dict[str, Any]] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                findings.extend(self._call_sink_findings(node))
            elif isinstance(node, ast.Assign):
                findings.extend(self._header_assign_findings(node))
        return findings

    def _call_sink_findings(self, node: ast.Call) -> list[dict[str, Any]]:
        rule_id = _sink_rule(node)
        if not rule_id:
            return []
        origins: list[str] = []
        tainted = False
        for a in list(node.args) + [k.value for k in node.keywords if k.value is not None]:
            o = self._expr_origin(a)
            if o:
                tainted = True
                if o not in origins:
                    origins.append(o)
        if not tainted:
            return []
        return [{
            "rule_id": rule_id,
            "line": getattr(node, "lineno", 0) or 0,
            "col": getattr(node, "col_offset", 0),
            "chain": " -> ".join(origins) if origins else "taint source",
        }]

    def _header_assign_findings(self, node: ast.Assign) -> list[dict[str, Any]]:
        """response.headers['Location'] = <tainted> — subscript assignment sinks."""
        findings: list[dict[str, Any]] = []
        for t in node.targets:
            if not (isinstance(t, ast.Subscript) and isinstance(t.value, (ast.Attribute, ast.Name))):
                continue
            if isinstance(t.value, ast.Attribute):
                if t.value.attr.lower() not in ("headers", "header"):
                    continue
            else:
                # Django style: response['Location'] = <tainted>
                key = t.slice
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    continue
                if key.value.lower() not in ("location", "set-cookie"):
                    continue
                owner = t.value.id.lower()
                if "resp" not in owner:
                    continue
            o = self._expr_origin(node.value)
            if not o:
                continue
            findings.append({
                "rule_id": "PY-026",
                "line": getattr(node, "lineno", 0) or 0,
                "col": getattr(node, "col_offset", 0),
                "chain": o,
            })
        return findings


# ---------------------------------------------------------------------------
# public interface
# ---------------------------------------------------------------------------

SINK_MESSAGES = {
    "PY-001": "User input reaches eval/exec (code injection, taint confirmed) | 用户输入进入 eval/exec（代码注入，污点已确认）",
    "PY-002": "User input reaches a system command (command injection, taint confirmed) | 用户输入进入系统命令（命令注入，污点已确认）",
    "PY-003": "User input reaches a shell=True subprocess call (command injection, taint confirmed) | 用户输入进入 shell=True 的 subprocess 调用（命令注入，污点已确认）",
    "PY-004": "User input reaches pickle/marshal deserialization (RCE, taint confirmed) | 用户输入进入 pickle/marshal 反序列化（RCE，污点已确认）",
    "PY-005": "User input reaches yaml.load (unsafe deserialization, taint confirmed) | 用户输入进入 yaml.load（不安全反序列化，污点已确认）",
    "PY-024": "User input reaches a redirect target (open redirect, taint confirmed) | 用户输入进入重定向目标（开放重定向，污点已确认）",
    "PY-025": "User input is written into an HTTP response body (reflected XSS, taint confirmed) | 用户输入写入 HTTP 响应体（反射型 XSS，污点已确认）",
    "PY-026": "User input builds an HTTP response header (header injection/open redirect, taint confirmed) | 用户输入构造 HTTP 响应头（响应头注入/开放重定向，污点已确认）",
    "PY-027": "User input reaches a logging call (log injection, taint confirmed) | 用户输入进入日志调用（日志注入，污点已确认）",
    "PY-028": "User input is compiled as a regex (ReDoS, taint confirmed) | 用户输入被编译为正则（ReDoS，污点已确认）",
    "PY-029": "User input reaches an XPath query (XPath injection, taint confirmed) | 用户输入进入 XPath 查询（XPath 注入，污点已确认）",
    "PY-030": "User input reaches a search filter (LDAP-style injection, taint confirmed) | 用户输入进入搜索过滤器（LDAP 风格注入，污点已确认）",
    "PY-031": "User input reaches a NoSQL filter expression (NoSQL injection, taint confirmed) | 用户输入进入 NoSQL 过滤表达式（NoSQL 注入，污点已确认）",
    "PY-032": "User input reaches file access (path traversal, taint confirmed) | 用户输入进入文件访问（路径穿越，污点已确认）",
    "PY-047": "User input reaches XML parsing (XXE/entity expansion, taint confirmed) | 用户输入进入 XML 解析（XXE/实体扩展，污点已确认）",
    "PY-048": "User input reaches a file save path (unvalidated upload, taint confirmed) | 用户输入进入文件保存路径（上传未校验，污点已确认）",
}

SINK_FIX_HINTS = {
    "PY-001": "Stop eval/exec on user input now; use json.loads / ast.literal_eval / explicit logic dispatch | 立即停止 eval/exec 处理用户输入，改用 json.loads / ast.literal_eval / 显式逻辑分发",
    "PY-002": "Use subprocess.run(argument list, shell=False); pass user input as a list element; never concatenate command strings | 改用 subprocess.run(参数列表, shell=False)，用户输入作为列表元素传递，禁止拼命令字符串",
    "PY-003": "Remove shell=True; pass command and args as a list; keep user input out of shell parsing | 移除 shell=True；命令与参数用列表传递，用户输入不进入 shell 解析",
    "PY-004": "Use safe formats like json.loads for external data; never pickle.loads on network/user input | 外部数据改用 json.loads 等安全格式；绝不 pickle.loads 网络/用户输入",
    "PY-005": "Use yaml.safe_load (or yaml.load(..., Loader=yaml.SafeLoader)) | 改用 yaml.safe_load（或 yaml.load(..., Loader=yaml.SafeLoader)）",
    "PY-024": "Validate the redirect target against a fixed URL whitelist (scheme+host); never redirect to raw request values | 用固定 URL 白名单（scheme+host）校验重定向目标，绝不直接重定向到请求值",
    "PY-025": "Escape/serialize user input before putting it into a response; use template autoescaping, never string-concat HTML | 用户输入进响应前先转义/序列化；使用模板自动转义，禁止字符串拼接 HTML",
    "PY-026": "Validate header values against a whitelist; use framework redirect helpers; reject CR/LF and raw URLs | 响应头值用白名单校验；用框架重定向辅助函数；拒绝 CR/LF 与原始 URL",
    "PY-027": "Do not log raw user input; use lazy %s formatting with a sanitizer or a structured logger | 不要记录原始用户输入；用惰性 %s 格式化并配合清洗或结构化日志",
    "PY-028": "Never compile regexes from user input; use a fixed pattern whitelist or cap input length | 绝不编译用户输入的正则；用固定模式白名单或限制输入长度",
    "PY-029": "Parameterize XPath queries (e.g. variables in lxml) and escape user input | XPath 查询参数化（如 lxml 变量绑定）并转义用户输入",
    "PY-030": "Escape LDAP special characters in user input or use server-side parameterized filters | 转义用户输入中的 LDAP 特殊字符，或使用服务端参数化过滤器",
    "PY-031": "Build filter expressions with placeholders; never concatenate user input into FilterExpression | 过滤表达式用占位符构造，禁止把用户输入拼接进 FilterExpression",
    "PY-032": "Normalize and validate file paths against a fixed base directory before open/send_file | open/send_file 前将路径规范化并校验其位于固定基础目录内",
    "PY-047": "Use defusedxml for untrusted XML (disables external entities); or xml.etree with entity resolution off | 不可信 XML 改用 defusedxml（禁用外部实体）",
    "PY-048": "Sanitize the upload filename (basename only) and validate the target directory before saving | 保存前清洗上传文件名（仅取 basename）并校验目标目录",
}

TAINT_CWE = {
    "PY-001": "CWE-95",
    "PY-002": "CWE-78",
    "PY-003": "CWE-78",
    "PY-004": "CWE-502",
    "PY-005": "CWE-502",
    "PY-024": "CWE-601",
    "PY-025": "CWE-79",
    "PY-026": "CWE-113",
    "PY-027": "CWE-117",
    "PY-028": "CWE-1333",
    "PY-029": "CWE-643",
    "PY-030": "CWE-90",
    "PY-031": "CWE-943",
    "PY-032": "CWE-22",
    "PY-047": "CWE-611",
    "PY-048": "CWE-434",
}


def find_tainted_sinks(code: str) -> list[dict[str, Any]]:
    """Analyze code and return the list of taint-confirmed sinks."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    eng = _TaintEngine(tree)
    eng.analyze()
    return eng.find_sinks()


def register_sanitizers(names: list[str] | tuple | set) -> int:
    """Merge user-configured sanitizer functions into the allowlist (config.yaml
    `validator.sanitizers`). Accepts fully-qualified names ("myapp.clean") or bare
    tails ("clean"); bare tails match any dotted path ending with them, exactly
    like the built-in allowlist. Returns the number of names added.

    Safety note: only add functions you have verified neutralize the tainted value
    (escape/quote/parameterize). Adding a non-sanitizing function can hide real
    vulnerabilities from the taint engine.
    """
    added = 0
    global _SANITIZER_TAILS
    for raw in names:
        if not isinstance(raw, str) or not raw.strip():
            continue
        name = raw.strip()
        if name in SANITIZERS:
            continue
        SANITIZERS.add(name)
        added += 1
    _SANITIZER_TAILS = frozenset(s.split(".")[-1] for s in SANITIZERS)
    return added

