"""Intra-procedural taint tracking using tree-sitter ASTs.

For every function, parses the AST and tracks taint flow through:
- Variable assignments
- Function call arguments
- Return values
- Field accesses
- String operations
- Conditional branches (taint preserved across all paths)

Outputs: for each function, a map of which variables are tainted and the
data flow edges that made them tainted.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TREE_SITTER_AVAILABLE = False
TREE_SITTER_PARSER: Any = None

try:
    from tree_sitter import Parser as TSParser, Language
    TREE_SITTER_AVAILABLE = True
    TREE_SITTER_PARSER = TSParser
except ImportError:
    pass

LANGUAGE_PARSERS: dict[str, Any] = {}

if TREE_SITTER_AVAILABLE:
    _TS_MODULES = {
        "python": ("tree_sitter_python", "language"),
        "javascript": ("tree_sitter_javascript", "language"),
        "typescript": ("tree_sitter_typescript", "language_tsx"),
        "java": ("tree_sitter_java", "language"),
        "c": ("tree_sitter_c", "language"),
        "cpp": ("tree_sitter_cpp", "language"),
        "go": ("tree_sitter_go", "language"),
        "rust": ("tree_sitter_rust", "language"),
        "csharp": ("tree_sitter_c_sharp", "language"),
    }
    for lang_name, (module_name, attr) in _TS_MODULES.items():
        try:
            mod = __import__(module_name)
            lang_obj = getattr(mod, attr)()
            LANGUAGE_PARSERS[lang_name] = lang_obj
        except (ImportError, AttributeError):
            pass


@dataclass
class TaintEdge:
    source_var: str
    target_var: str
    operation: str
    line: int
    is_tainted: bool = True


@dataclass
class TaintState:
    function_name: str
    file: str
    tainted_vars: set[str] = field(default_factory=set)
    clean_vars: set[str] = field(default_factory=set)
    edges: list[TaintEdge] = field(default_factory=list)
    param_taint: dict[str, str] = field(default_factory=dict)
    return_taint: set[str] = field(default_factory=set)
    sink_reaches: list[dict] = field(default_factory=list)


def _get_parsers() -> dict[str, Any]:
    parsers = {}
    for lang, lang_obj in LANGUAGE_PARSERS.items():
        try:
            parser = TREE_SITTER_PARSER()
            parser.set_language(Language(lang_obj))
            parsers[lang] = parser
        except Exception:
            pass
    return parsers


_PARSERS: dict[str, Any] = {}
_PARSERS_LOADED = False


def _ensure_parsers():
    global _PARSERS, _PARSERS_LOADED
    if not _PARSERS_LOADED:
        _PARSERS = _get_parsers()
        _PARSERS_LOADED = True
    return _PARSERS


def _get_identifier_name(node, source: str) -> str:
    if node is None:
        return ""
    if node.type in ("identifier", "name", "field_identifier", "property_identifier",
                     "type_identifier", "identifier_name"):
        return source[node.start_byte:node.end_byte]
    for child in node.children:
        if child.type in ("identifier", "name", "field_identifier", "property_identifier"):
            return source[child.start_byte:child.end_byte]
    return ""


NOISE_FUNCTIONS = {
    "print", "log", "logger.", "logging.", "writeln", "Write-Host",
    "echo", "fmt.Println", "fmt.Printf", "System.out.println",
    "console.log", "dump", "var_dump", "toString", "__repr__",
    "__str__", "str", "repr", "format", "len", "type", "isinstance",
}

SANITIZER_FUNCTIONS = {
    "html.escape", "html_escape", "escape_html", "sanitize_html", "sanitize",
    "bleach.clean", "strip_tags", "DOMPurify.sanitize", "xss_filter",
    "shlex.quote", "quote", "pipes.quote", "shell_quote",
    "os.path.normpath", "os.path.realpath", "Path.resolve", "secure_filename",
    "safe_join", "validate_filename", "pathlib.Path.resolve",
    "yaml.safe_load", "json.loads", "msgpack.unpackb",
    "int.parse", "float.parse", "intval", "parseInt", "parseFloat",
    "re.match", "re.fullmatch", "re.search",
    "htmlspecialchars", "htmlentities", "urlencode", "rawurlencode",
    "mysql_real_escape_string", "mysqli_real_escape_string", "pg_escape_string",
    "urllib.parse.quote", "urllib.parse.quote_plus", "encodeURIComponent",
    "validate_email", "validate_url", "validate_ip",
    "bcrypt.hash", "bcrypt.verify", "password_hash", "argon2.hash",
    "jwt.verify", "jwt.decode", "verify_signature",
    "canReadFile", "isPathSafe", "isInDirectory", "isAuthorized",
    "authorize", "checkPermission", "requirePermission",
    "Authentication.verify", "isAuthenticated", "isAdmin",
}


def _is_sanitizer_call(function_name: str) -> bool:
    fn_lower = function_name.lower().replace("()", "").replace("(", "").replace(")", "")
    for sanitizer in SANITIZER_FUNCTIONS:
        s_lower = sanitizer.lower()
        if fn_lower == s_lower or fn_lower.endswith("." + s_lower):
            return True
    return False


def _extract_called_name(node, source: str) -> str:
    if node is None:
        return ""
    if node.type == "identifier":
        return source[node.start_byte:node.end_byte]
    if node.type == "attribute":
        obj = _get_identifier_name(node.child_by_field_name("object"), source)
        attr = _get_identifier_name(node.child_by_field_name("attribute"), source)
        return f"{obj}.{attr}" if obj and attr else (attr or obj)
    if node.type == "member_expression":
        obj = _get_identifier_name(node.child_by_field_name("object"), source)
        prop = _get_identifier_name(node.child_by_field_name("property"), source)
        return f"{obj}.{prop}" if obj and prop else (prop or obj)
    if node.type == "field_expression":
        obj = _get_identifier_name(node.child_by_field_name("argument"), source)
        field = _get_identifier_name(node.child_by_field_name("field"), source)
        return f"{obj}.{field}" if obj and field else (field or obj)
    return _get_identifier_name(node, source)


def _get_call_name_and_args(node, source: str, language: str) -> tuple[str, list[str]]:
    if node.type not in ("call", "call_expression", "method_invocation", "invocation_expression"):
        return "", []

    func_node = node.child_by_field_name("function") or node.child_by_field_name("name")
    if func_node is None and node.children:
        func_node = node.children[0]

    func_name = _extract_called_name(func_node, source) if func_node else ""

    args = []
    args_node = None
    for child in node.children:
        if child.type in ("argument_list", "arguments", "argument_list"):
            args_node = child
            break

    if args_node:
        for child in args_node.children:
            if child.type in ("(", ")", ",", "(", ")"):
                continue
            arg_text = source[child.start_byte:child.end_byte].strip()
            if arg_text:
                args.append(arg_text)

    return func_name, args


class IntraTaintTracker:
    def __init__(self):
        self.parsers = _ensure_parsers()
        self.global_vars: dict[str, set[str]] = {}
        self.class_vars: dict[str, set[str]] = {}

    def trace_function(self, function_body: str, function_name: str, file: str,
                       language: str, source_tag_vars: set[str],
                       param_names: set[str] | None = None) -> TaintState:
        state = TaintState(function_name=function_name, file=file)
        if param_names:
            for p in param_names:
                if p in source_tag_vars:
                    state.tainted_vars.add(p)
                    state.param_taint[p] = "source"
                else:
                    state.clean_vars.add(p)
        for v in source_tag_vars:
            state.tainted_vars.add(v)

        if language not in self.parsers:
            self._trace_regex(function_body, state)
            return state

        self._trace_ast(function_body, state, language)
        return state

    def _trace_regex(self, body: str, state: TaintState):
        lines = body.split("\n")
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            assign_match = re.match(r'(\w+)\s*=\s*(.+)', line_stripped)
            if assign_match:
                target = assign_match.group(1)
                expr = assign_match.group(2)
                if any(re.search(r'\b' + re.escape(t) + r'\b', expr) for t in state.tainted_vars):
                    state.tainted_vars.add(target)
                    state.edges.append(TaintEdge(
                        source_var="expr", target_var=target,
                        operation="assignment", line=i,
                    ))

    def _trace_ast(self, body: str, state: TaintState, language: str):
        parser = self.parsers.get(language)
        if not parser:
            self._trace_regex(body, state)
            return

        try:
            tree = parser.parse(body.encode("utf-8"))
            root = tree.root_node
            self._walk_node(root, body, state, language)
        except Exception:
            self._trace_regex(body, state)

    def _walk_node(self, node, source: str, state: TaintState, language: str):
        if node.type in ("assignment", "augmented_assignment", "compound_assignment"):
            self._handle_assignment(node, source, state, language)
        elif node.type in ("variable_declarator", "short_var_declaration", "let_declaration"):
            self._handle_declaration(node, source, state, language)
        elif node.type in ("call", "call_expression", "method_invocation", "invocation_expression"):
            self._handle_call(node, source, state, language)
        elif node.type == "return_statement":
            self._handle_return(node, source, state, language)
        elif node.type == "if_statement":
            for child in node.children:
                if child.type in ("block", "statement_block", "if_body", "consequence"):
                    self._walk_node(child, source, state, language)
                elif child.type in ("else_clause", "elif_clause", "else_body"):
                    for sub in child.children:
                        if sub.type in ("block", "statement_block", "elif_body", "else_body", "consequence"):
                            self._walk_node(sub, source, state, language)
        elif node.type in ("for_statement", "for_range_statement", "while_statement", "do_statement"):
            for child in node.children:
                if child.type in ("block", "statement_block", "body"):
                    self._walk_node(child, source, state, language)
        elif node.type == "try_statement":
            for child in node.children:
                if child.type in ("block", "statement_block", "body"):
                    self._walk_node(child, source, state, language)
                if child.type in ("except_clause", "catch_clause", "catch_block"):
                    for sub in child.children:
                        if sub.type in ("block", "statement_block", "body"):
                            self._walk_node(sub, source, state, language)
        elif node.type in ("block", "statement_block", "compound_statement", "program",
                           "function_body", "body", "module", "source_file",
                           "class_body", "declaration_list", "compilation_unit"):
            for child in node.children:
                self._walk_node(child, source, state, language)
        else:
            for child in node.children:
                self._walk_node(child, source, state, language)

    def _handle_assignment(self, node, source: str, state: TaintState, language: str):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right") or node.child_by_field_name("value")
        if not left:
            for child in node.children:
                if child.type == "identifier":
                    left = child
                    break

        target = _get_identifier_name(left, source) if left else ""

        right_text = source[right.start_byte:right.end_byte] if right else ""
        right_refs_taint = any(
            re.search(r'\b' + re.escape(t) + r'\b', right_text)
            for t in state.tainted_vars
        )

        if target and right_refs_taint:
            if "." in target:
                parts = target.split(".", 1)
                if parts[0] in ("self", "this"):
                    if parts[0] not in self.class_vars:
                        self.class_vars[parts[0]] = set()
                    self.class_vars[parts[0]].add(parts[1])
                    state.tainted_vars.add(target)
            elif target in getattr(self, 'current_function_globals', set()):
                if target not in self.global_vars:
                    self.global_vars[target] = set()
                self.global_vars[target].add(target)

        is_tainted = right_refs_taint

        if target and is_tainted:
            state.tainted_vars.add(target)
            state.edges.append(TaintEdge(
                source_var="expression",
                target_var=target,
                operation="assignment",
                line=node.start_point[0] + 1,
            ))

    def _handle_declaration(self, node, source: str, state: TaintState, language: str):
        target = ""
        value = None

        for child in node.children:
            if child.type in ("identifier", "name", "field_identifier"):
                target = source[child.start_byte:child.end_byte]
            elif child.type in ("string_literal", "string", "number_literal",
                                 "number", "true", "false", "None", "null",
                                 "binary_expression", "call", "call_expression",
                                 "method_invocation", "identifier", "member_expression",
                                 "field_expression", "attribute", "parenthesized_expression",
                                 "unary_expression", "subscript", "array",
                                 "object", "dictionary", "list", "tuple", "set"):
                value = child

        if target and value:
            value_text = source[value.start_byte:value.end_byte]
            is_tainted = any(
                re.search(r'\b' + re.escape(t) + r'\b', value_text)
                for t in state.tainted_vars
            )
            if is_tainted:
                state.tainted_vars.add(target)
                state.edges.append(TaintEdge(
                    source_var=value_text[:50],
                    target_var=target,
                    operation="declaration",
                    line=node.start_point[0] + 1,
                ))

    def _handle_call(self, node, source: str, state: TaintState, language: str):
        func_name, args = _get_call_name_and_args(node, source, language)

        fn_lower = func_name.lower()
        for noise_fn in NOISE_FUNCTIONS:
            if noise_fn.lower() in fn_lower:
                return

        is_sanitizer = _is_sanitizer_call(func_name)

        for i, arg in enumerate(args):
            if any(re.search(r'\b' + re.escape(t) + r'\b', arg) for t in state.tainted_vars):
                state.sink_reaches.append({
                    "function": func_name,
                    "argument_index": i,
                    "argument_text": arg,
                    "line": node.start_point[0] + 1,
                    "tainted_vars": [
                        t for t in state.tainted_vars
                        if re.search(r'\b' + re.escape(t) + r'\b', arg)
                    ],
                    "is_sanitized": is_sanitizer,
                })

    def _handle_return(self, node, source: str, state: TaintState, language: str):
        for child in node.children:
            if child.type not in ("return", ";"):
                value_text = source[child.start_byte:child.end_byte]
                if any(re.search(r'\b' + re.escape(t) + r'\b', value_text)
                       for t in state.tainted_vars):
                    for t in state.tainted_vars:
                        if re.search(r'\b' + re.escape(t) + r'\b', value_text):
                            state.return_taint.add(t)


def trace_function_fully(function_body: str, function_name: str, file: str,
                          language: str, source_tag_vars: set[str],
                          param_names: set[str] | None = None) -> TaintState:
    tracker = IntraTaintTracker()
    return tracker.trace_function(function_body, function_name, file, language,
                                   source_tag_vars, param_names)
