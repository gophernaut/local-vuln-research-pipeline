"""Multi-language AST parser using tree-sitter — ALL 16 supported languages.

Extracts: functions, classes, method calls, imports, string literals,
assignments, entry points, and type information per language.

Tree-sitter languages: Python, JavaScript, TypeScript, Java, C, C++, Go, Rust, C#
Regex fallback: PHP, Ruby, PowerShell, Kotlin, Swift, Shell
"""
from __future__ import annotations

import re
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


def _ts_query(lang_obj, query_string: str):
    """Compile a tree-sitter query using the modern API."""
    if not TREE_SITTER_AVAILABLE:
        return None
    try:
        from tree_sitter import Query, QueryCursor, Language
        if not isinstance(lang_obj, Language):
            lang_obj = Language(lang_obj)
        lines = query_string.split("\n")
        non_empty = [l for l in lines if l.strip()]
        if non_empty:
            min_indent = min(len(l) - len(l.lstrip()) for l in non_empty)
            cleaned = "\n".join(l[min_indent:] if len(l) >= min_indent else l for l in lines)
        else:
            cleaned = query_string
        cleaned = cleaned.strip()
        query = Query(lang_obj, cleaned)
        return query
    except Exception:
        return None


def _ts_captures(query, node):
    """Run a compiled query and return captures dict."""
    if query is None:
        return {}
    try:
        from tree_sitter import QueryCursor
        cursor = QueryCursor(query)
        return cursor.captures(node)
    except Exception:
        return {}

LANGUAGE_EXTENSIONS = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala", ".sc": "scala",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp", ".csx": "csharp", ".vb": "csharp",
    ".rb": "ruby",
    ".php": "php", ".phtml": "php",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".swift": "swift",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
}

LANG_TO_EXT = {v: k for k, v in LANGUAGE_EXTENSIONS.items()}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
             "target", "build", "dist", "vendor", ".next", ".nuxt",
             ".idea", ".vscode", "bin", "obj", "Debug", "Release",
             "packages", "TestResults", ".deps", ".libs"}


@dataclass
class FunctionDef:
    name: str
    file: str
    line: int
    end_line: int
    params: list[str] = field(default_factory=list)
    body: str = ""
    is_exported: bool = False
    is_static: bool = False
    is_constructor: bool = False
    class_name: str = ""
    return_type: str = ""
    annotations: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    file: str
    line: int
    function_name: str
    arguments: list[str] = field(default_factory=list)
    caller_function: str = ""
    object_name: str = ""


@dataclass
class EntryPoint:
    file: str
    line: int
    type: str
    name: str
    description: str
    http_method: str = ""


@dataclass
class ImportInfo:
    file: str
    line: int
    module: str
    imported_names: list[str] = field(default_factory=list)
    alias: str = ""


@dataclass
class ClassDef:
    name: str
    file: str
    line: int
    end_line: int
    superclass: str = ""
    interfaces: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)


@dataclass
class Variable:
    name: str
    file: str
    line: int
    var_type: str = ""
    assigned_from: str = ""
    is_param: bool = False
    scope: str = ""


@dataclass
class FileAnalysis:
    path: str
    language: str
    functions: list[FunctionDef] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    class_definitions: list[ClassDef] = field(default_factory=list)
    variables: list[Variable] = field(default_factory=list)
    lines: int = 0
    raw_source: str = ""


class ASTParser:
    def __init__(self):
        self._parsers: dict[str, Any] = {}
        if TREE_SITTER_AVAILABLE:
            for lang, lang_obj in LANGUAGE_PARSERS.items():
                try:
                    wrapped = Language(lang_obj)
                    parser = TREE_SITTER_PARSER(wrapped)
                    self._parsers[lang] = parser
                except Exception:
                    try:
                        parser = TREE_SITTER_PARSER()
                        parser.set_language(Language(lang_obj))
                        self._parsers[lang] = parser
                    except Exception:
                        pass

    def parse_file(self, filepath: Path) -> FileAnalysis | None:
        ext = filepath.suffix.lower()
        language = LANGUAGE_EXTENSIONS.get(ext)
        if not language:
            return None

        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return None

        relative_path = str(filepath.relative_to(filepath.anchor)) if filepath.is_absolute() else str(filepath)

        if language in self._parsers:
            return self._parse_with_tree_sitter(source, relative_path, language)

        return self._parse_with_regex(source, relative_path, language)

    def _parse_with_tree_sitter(self, source: str, path: str, language: str) -> FileAnalysis:
        analysis = FileAnalysis(path=path, language=language, lines=source.count("\n"), raw_source=source)
        parser = self._parsers[language]
        tree = parser.parse(source.encode("utf-8"))
        root = tree.root_node

        try:
            self._extract_functions(root, source, analysis)
        except Exception:
            pass
        try:
            self._extract_call_sites(root, source, analysis)
        except Exception:
            pass
        try:
            self._extract_entry_points(root, source, analysis)
        except Exception:
            pass
        try:
            self._extract_imports(root, source, analysis)
        except Exception:
            pass
        try:
            self._extract_classes(root, source, analysis)
        except Exception:
            pass
        try:
            self._extract_variables(root, source, analysis)
        except Exception:
            pass

        return analysis

    def parse_directory(self, repo_path: Path) -> list[FileAnalysis]:
        results = []
        files = []
        for ext in LANGUAGE_EXTENSIONS:
            files.extend(repo_path.rglob(f"*{ext}"))

        for filepath in files:
            if any(d in filepath.parts for d in SKIP_DIRS):
                continue
            analysis = self.parse_file(filepath)
            if analysis:
                results.append(analysis)

        return results

    def _extract_functions(self, node, source: str, analysis: FileAnalysis):
        lang = analysis.language
        parser_obj = self._parsers.get(lang)
        if parser_obj is None:
            return
        lang_obj = parser_obj.language

        queries = {
            "python": """(function_definition
                    name: (identifier) @name
                    parameters: (parameters) @params
                    body: (block) @body) @func""",
            "javascript": """(function_declaration
                    name: (identifier) @name
                    parameters: (formal_parameters) @params
                    body: (statement_block) @body) @func""",
            "typescript": """(function_declaration
                    name: (identifier) @name
                    parameters: (formal_parameters) @params
                    body: (statement_block) @body) @func""",
            "java": """(method_declaration
                    name: (identifier) @name
                    parameters: (formal_parameters) @params
                    body: (block) @body) @func""",
            "c": """(function_definition
                    declarator: (function_declarator
                        declarator: (identifier) @name)
                    body: (compound_statement) @body) @func""",
            "cpp": """(function_definition
                    declarator: (function_declarator
                        declarator: [(identifier) @name
                                      (field_identifier) @name
                                      (qualified_identifier) @name])
                    body: (compound_statement) @body) @func""",
            "go": """(function_declaration
                    name: (identifier) @name
                    parameters: (parameter_list) @params
                    body: (block) @body) @func""",
            "rust": """(function_item
                    name: (identifier) @name
                    parameters: (parameters) @params
                    body: (block) @body) @func""",
            "csharp": """(method_declaration
                    name: (identifier) @name
                    parameters: (parameter_list) @params
                    body: (block) @body) @func
                (constructor_declaration
                    name: (identifier) @name
                    parameters: (parameter_list) @params
                    body: (block) @body) @func""",
        }

        query_str = queries.get(lang)
        if not query_str:
            return

        query = _ts_query(lang_obj, query_str)
        if query is None:
            return

        captures = _ts_captures(query, node)
        if not captures:
            return

        func_nodes_list: list = []
        body_nodes: list = []
        params_nodes: list = []
        name_nodes: list = []

        for cap_name, nodes in captures.items():
            if cap_name == "func":
                for n in nodes:
                    func_nodes_list.append(n)
            elif cap_name == "name":
                name_nodes = nodes
            elif cap_name == "params":
                params_nodes = nodes
            elif cap_name == "body":
                body_nodes = nodes

        for func_node in func_nodes_list:
            fdata = {"node": func_node}
            func_start = func_node.start_byte
            func_end = func_node.end_byte

            for nn in name_nodes:
                if func_start <= nn.start_byte < func_end:
                    fdata["name"] = source[nn.start_byte:nn.end_byte]
                    break

            for pn in params_nodes:
                if func_start <= pn.start_byte < func_end:
                    fdata["params_text"] = source[pn.start_byte:pn.end_byte]
                    break

            for bn in body_nodes:
                if func_start <= bn.start_byte < func_end:
                    fdata["body"] = source[bn.start_byte:bn.end_byte]
                    fdata["end_line"] = bn.end_point[0] + 1
                    break

            if "name" not in fdata:
                continue

            class_name = self._find_enclosing_class_name(func_node, source)
            is_static = False
            if class_name and func_node.parent:
                for sibling in func_node.parent.children:
                    if sibling.type == "decorator":
                        dec_text = source[sibling.start_byte:sibling.end_byte]
                        if "staticmethod" in dec_text:
                            is_static = True
                        if "classmethod" in dec_text:
                            is_static = True

            analysis.functions.append(FunctionDef(
                name=fdata["name"],
                file=analysis.path,
                line=func_node.start_point[0] + 1,
                end_line=fdata.get("end_line", func_node.end_point[0] + 1),
                body=fdata.get("body", ""),
                is_constructor=(
                    fdata["name"] == "__init__"
                    or func_node.type == "constructor_declaration"
                    or (class_name and fdata["name"] == class_name)
                ),
                is_static=is_static,
                class_name=class_name,
                params=self._extract_param_names(fdata.get("params_text", ""), lang),
            ))

    def _find_enclosing_class_name(self, func_node, source: str) -> str:
        current = func_node.parent
        while current is not None:
            if current.type in ("class_definition", "class_declaration",
                                "class_specifier", "struct_item", "impl_item",
                                "trait_item", "interface_declaration"):
                for child in current.children:
                    if child.type in ("identifier", "name", "type_identifier"):
                        return source[child.start_byte:child.end_byte]
                return ""
            current = current.parent
        return ""

    def _extract_param_names(self, params_text: str, lang: str) -> list[str]:
        if not params_text:
            return []
        params_text = params_text.strip("()").strip()
        if not params_text:
            return []
        parts = [p.strip() for p in params_text.split(",")]
        names = []
        for p in parts:
            if not p:
                continue
            if lang in ("python",):
                tokens = p.split(":")
                if tokens:
                    names.append(tokens[0].strip().lstrip("*").lstrip("&").split()[-1])
            elif lang in ("java", "csharp"):
                tokens = p.split()
                if tokens:
                    names.append(tokens[-1])
            elif lang in ("javascript", "typescript", "go", "rust"):
                tokens = p.split()
                if tokens:
                    names.append(tokens[0].lstrip("&").lstrip("*"))
            elif lang in ("c", "cpp"):
                tokens = p.replace("const", "").replace("volatile", "").split()
                if tokens:
                    names.append(tokens[-1].lstrip("*").lstrip("&"))
            else:
                tokens = p.split()
                if tokens:
                    names.append(tokens[-1].lstrip("*").lstrip("&"))
        return [n for n in names if n.isidentifier()]

    def _extract_call_sites(self, node, source: str, analysis: FileAnalysis):
        lang = analysis.language
        parser_obj = self._parsers.get(lang)
        if parser_obj is None:
            return
        lang_obj = parser_obj.language

        queries = {
            "python": """(call
                    function: [(identifier) @func_name
                              (attribute
                                attribute: (identifier) @attr)]
                    arguments: (argument_list) @args) @call""",
            "javascript": """(call_expression
                    function: [(identifier) @func_name
                              (member_expression
                                property: (property_identifier) @attr)]
                    arguments: (arguments) @args) @call""",
            "typescript": """(call_expression
                    function: [(identifier) @func_name
                              (member_expression
                                property: (property_identifier) @attr)]
                    arguments: (arguments) @args) @call""",
            "java": """(method_invocation
                    name: (identifier) @func_name
                    arguments: (argument_list) @args) @call""",
            "c": """(call_expression
                    function: (identifier) @func_name
                    arguments: (argument_list) @args) @call""",
            "cpp": """(call_expression
                    function: [(identifier) @func_name
                              (field_expression
                                field: (field_identifier) @attr)]
                    arguments: (argument_list) @args) @call""",
            "go": """(call_expression
                    function: [(identifier) @func_name
                              (selector_expression
                                field: (field_identifier) @attr)]
                    arguments: (argument_list) @args) @call""",
            "rust": """(call_expression
                    function: [(identifier) @func_name
                              (field_expression
                                field: (field_identifier) @attr)]
                    arguments: (arguments) @args) @call""",
            "csharp": """(invocation_expression
                    function: [(identifier) @func_name
                              (member_access_expression
                                name: (identifier) @attr)]
                    arguments: (argument_list) @args) @call""",
        }

        query_str = queries.get(lang)
        if not query_str:
            return

        query = _ts_query(lang_obj, query_str)
        if query is None:
            return

        captures = _ts_captures(query, node)
        if not captures:
            return

        call_nodes: dict[int, dict] = {}
        for cap_name, cap_nodes in captures.items():
            for cap_node in cap_nodes:
                call_key = cap_node.start_byte
                if cap_name == "call":
                    call_nodes.setdefault(call_key, {})["call_node"] = cap_node
                elif cap_name == "func_name":
                    call_nodes.setdefault(call_key, {})["func_name"] = source[cap_node.start_byte:cap_node.end_byte]
                    call_nodes.setdefault(call_key, {})["func_node"] = cap_node
                elif cap_name == "attr":
                    call_nodes.setdefault(call_key, {})["func_name"] = source[cap_node.start_byte:cap_node.end_byte]
                    call_nodes.setdefault(call_key, {})["attr_node"] = cap_node
                elif cap_name == "args":
                    call_nodes.setdefault(call_key, {})["args_node"] = cap_node

        seen_calls = set()
        for call_key, call_data in call_nodes.items():
            func_name = call_data.get("func_name", "")
            if not func_name or len(func_name) > 100:
                continue

            func_node = call_data.get("func_node") or call_data.get("attr_node")
            line = (func_node.start_point[0] + 1) if func_node else 0
            if (line, func_name) in seen_calls:
                continue
            seen_calls.add((line, func_name))

            obj_name = ""
            if func_node and func_node.parent and func_node.parent.type in (
                "member_expression", "field_expression",
                "selector_expression", "attribute", "method_invocation",
                "call",
            ):
                obj_field = func_node.parent.child_by_field_name("object")
                if obj_field is None and func_node.parent.type == "method_invocation":
                    obj_field = func_node.parent.child_by_field_name("object")
                if obj_field is None and func_node.parent.type == "call":
                    if func_node.parent.parent and func_node.parent.parent.type == "call":
                        for sib in func_node.parent.parent.children:
                            if sib.type == "attribute" and sib != func_node.parent:
                                obj_field = sib.child_by_field_name("object")
                                break
                if obj_field:
                    obj_name = source[obj_field.start_byte:obj_field.end_byte]

            arguments = []
            args_node = call_data.get("args_node")
            if args_node:
                args_text = source[args_node.start_byte:args_node.end_byte]
                arguments = self._extract_argument_names(args_text, lang)

            analysis.call_sites.append(CallSite(
                file=analysis.path,
                line=line,
                function_name=func_name,
                object_name=obj_name,
                arguments=arguments,
            ))

    def _extract_entry_points(self, node, source: str, analysis: FileAnalysis):
        lang = analysis.language
        if lang in ("python",):
            self._python_entry_points(source, analysis)
        elif lang in ("javascript", "typescript"):
            self._js_entry_points(source, analysis)
        elif lang == "java":
            self._java_entry_points(source, analysis)
        elif lang == "kotlin":
            self._kotlin_entry_points(source, analysis)
        elif lang == "scala":
            self._scala_entry_points(source, analysis)
        elif lang in ("c", "cpp"):
            self._native_entry_points(source, analysis)
        elif lang == "go":
            self._go_entry_points(source, analysis)
        elif lang == "rust":
            self._rust_entry_points(source, analysis)
        elif lang == "csharp":
            self._csharp_entry_points(source, analysis)
        elif lang == "ruby":
            self._ruby_entry_points(source, analysis)
        elif lang == "php":
            self._php_entry_points(source, analysis)
        elif lang == "powershell":
            self._powershell_entry_points(source, analysis)
        elif lang == "swift":
            self._swift_entry_points(source, analysis)
        elif lang == "shell":
            self._shell_entry_points(source, analysis)

    def _python_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"@app\.(route|get|post|put|delete|patch|options|head)\s*\(", "HTTP_ROUTE"),
            (r"@router\.(get|post|put|delete|patch|options)\s*\(", "HTTP_ROUTE"),
            (r"@blueprint\.route\s*\(", "HTTP_ROUTE"),
            (r"@api\.(get|post|put|delete|patch)\s*\(", "HTTP_ROUTE"),
            (r"if\s+__name__\s*==\s*['\"]__main__['\"]", "MAIN_ENTRY"),
            (r"def\s+main\s*\(", "MAIN_ENTRY"),
            (r"argparse\.ArgumentParser", "CLI"),
            (r"click\.(command|group)", "CLI"),
            (r"typer\.Typer", "CLI"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                http_method = ""
                if ep_type == "HTTP_ROUTE":
                    http_method = m.group(1).upper() if m.group(1) else "GET"
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                    http_method=http_method,
                ))

        route_param_pattern = r"@app\.route\s*\(\s*['\"][^'\"]*<(\w+)>[^'\"]*['\"]"
        for m in re.finditer(route_param_pattern, source):
            param_name = m.group(1)
            line = source[:m.start()].count("\n") + 1
            analysis.entry_points.append(EntryPoint(
                file=analysis.path, line=line, type="HTTP_ROUTE",
                name=f"route_param_{param_name}",
                description=f"Route parameter: {param_name}",
                http_method="GET",
            ))

    def _js_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"app\.(get|post|put|delete|patch|use|all)\s*\(", "HTTP_ROUTE"),
            (r"router\.(get|post|put|delete|patch|use|all)\s*\(", "HTTP_ROUTE"),
            (r"server\.listen\s*\(", "SERVER_LISTEN"),
            (r"module\.exports", "EXPORT"),
            (r"process\.argv", "CLI"),
            (r"app\.listen\s*\(", "SERVER_LISTEN"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                http_method = ""
                if ep_type == "HTTP_ROUTE":
                    http_method = m.group(1).upper() if m.group(1) else "GET"
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                    http_method=http_method,
                ))

    def _java_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|PatchMapping)\s*\(", "HTTP_ROUTE"),
            (r"public\s+static\s+void\s+main\s*\(", "MAIN_ENTRY"),
            (r"HttpServlet", "SERVLET"),
            (r"@WebServlet", "SERVLET"),
            (r"@RestController", "REST_CONTROLLER"),
            (r"@Controller", "CONTROLLER"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                http_method = ""
                if ep_type == "HTTP_ROUTE":
                    name = m.group(0).lower()
                    if "get" in name: http_method = "GET"
                    elif "post" in name: http_method = "POST"
                    elif "put" in name: http_method = "PUT"
                    elif "delete" in name: http_method = "DELETE"
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                    http_method=http_method,
                ))

    def _native_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"\bmain\s*\(\s*(?:int|void)\s+\w+\s*,\s*(?:char|wchar_t)\s*\*\s*\w+\s*\[\s*\]", "MAIN_ENTRY"),
            (r"\bWinMain\s*\(", "MAIN_ENTRY"),
            (r"\bDllMain\s*\(", "DLL_ENTRY"),
            (r"\bEXPORT\s+\w+\s+__cdecl\s+\w+", "EXPORTED_FUNC"),
            (r"\b__declspec\s*\(\s*dllexport\s*\)", "EXPORTED_FUNC"),
            (r"\bSYSCALL_DEFINE\d*\s*\(", "SYSCALL"),
            (r"\bioctl\s*\(", "IOCTL_HANDLER"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _go_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"func\s+main\s*\(\s*\)", "MAIN_ENTRY"),
            (r"http\.HandleFunc\s*\(", "HTTP_ROUTE"),
            (r"http\.ListenAndServe\s*\(", "SERVER_LISTEN"),
            (r"net\.Listen\s*\(", "SERVER_LISTEN"),
            (r"func\s+\w+\s*\(\s*w\s+http\.ResponseWriter", "HTTP_HANDLER"),
            (r"grpc\.NewServer\s*\(", "GRPC_SERVER"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _rust_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"fn\s+main\s*\(", "MAIN_ENTRY"),
            (r"#\[actix_web::main\]", "ACTIX_MAIN"),
            (r"#\[tokio::main\]", "TOKIO_MAIN"),
            (r"async\s+fn\s+\w+\s*\(\s*\w+:\s*Request", "HTTP_HANDLER"),
            (r"#\[get\s*\(", "HTTP_ROUTE"),
            (r"#\[post\s*\(", "HTTP_ROUTE"),
            (r"#\[put\s*\(", "HTTP_ROUTE"),
            (r"#\[delete\s*\(", "HTTP_ROUTE"),
            (r"#\[no_mangle\]", "EXPORTED_FUNC"),
            (r"pub\s+extern\s+\"C\"", "FFI_EXPORT"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _csharp_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"\[Http(Get|Post|Put|Delete|Patch)\s*\(", "HTTP_ROUTE"),
            (r"static\s+void\s+Main\s*\(", "MAIN_ENTRY"),
            (r"public\s+static\s+int\s+Main\s*\(", "MAIN_ENTRY"),
            (r"static\s+async\s+Task\s+Main\s*\(", "MAIN_ENTRY"),
            (r"\[ApiController\]", "API_CONTROLLER"),
            (r"\[Authorize\s*\(", "AUTH_ENDPOINT"),
            (r"app\.Map(Get|Post|Put|Delete)\s*\(", "MINIMAL_API"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                http_method = ""
                if ep_type in ("HTTP_ROUTE", "MINIMAL_API"):
                    name = m.group(0).lower()
                    if "get" in name: http_method = "GET"
                    elif "post" in name: http_method = "POST"
                    elif "put" in name: http_method = "PUT"
                    elif "delete" in name: http_method = "DELETE"
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                    http_method=http_method,
                ))

    def _ruby_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"(get|post|put|delete|patch|match)\s+['\"/]", "HTTP_ROUTE"),
            (r"get\s+['\"]/", "HTTP_ROUTE"),
            (r"post\s+['\"]/", "HTTP_ROUTE"),
            (r"put\s+['\"]/", "HTTP_ROUTE"),
            (r"delete\s+['\"]/", "HTTP_ROUTE"),
            (r"Rack::Builder", "RACK_SERVER"),
            (r"WEBrick", "WEBSERVER"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _php_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)", "HTTP_REQUEST"),
            (r"\bphp://input\b", "HTTP_BODY"),
            (r"define\s*\(\s*['\"]", "CONST"),
            (r"class\s+\w+\s+extends\s+(?:Controller|ApiController)", "CONTROLLER"),
            (r"\bRoute::", "LARAVEL_ROUTE"),
            (r"\bapp\(\s*['\"]router['\"]", "LARAVEL_ROUTE"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _powershell_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"function\s+\w+-\w+", "CMDLET"),
            (r"\bparam\s*\(", "PARAM_BLOCK"),
            (r"\bCmdletBinding\s*\(", "CMDLET"),
            (r"\[CmdletBinding\s*\(", "CMDLET"),
            (r"\bBegin\s*\{", "BEGIN_BLOCK"),
            (r"\bProcess\s*\{", "PROCESS_BLOCK"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _kotlin_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"@GetMapping\b", "HTTP_ROUTE"),
            (r"@PostMapping\b", "HTTP_ROUTE"),
            (r"@PutMapping\b", "HTTP_ROUTE"),
            (r"@DeleteMapping\b", "HTTP_ROUTE"),
            (r"@RequestMapping\b", "HTTP_ROUTE"),
            (r"@RestController\b", "REST_CONTROLLER"),
            (r"@Controller\b", "CONTROLLER"),
            (r"fun\s+main\s*\(", "MAIN_ENTRY"),
            (r"\bServlet\s*\(", "SERVLET"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _scala_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"@(?:Get|Post|Put|Delete|Request)Mapping", "HTTP_ROUTE"),
            (r"def\s+main\s*\(", "MAIN_ENTRY"),
            (r"extends\s+Controller\b", "CONTROLLER"),
            (r"@Path\s*\(", "JAX_RS"),
            (r"@GET|@POST|@PUT|@DELETE", "JAX_RS"),
            (r"object\s+\w+\s+extends\s+App", "MAIN_ENTRY"),
            (r"def\s+\w+\s*\([^)]*Request\b", "HTTP_HANDLER"),
            (r"play\.api\.mvc\.\w+", "PLAY_ROUTE"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _swift_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"func\s+main\s*\(", "MAIN_ENTRY"),
            (r"@main\s+", "MAIN_ENTRY"),
            (r"@UIApplicationMain", "APP_ENTRY"),
            (r"@AppDelegate", "APP_ENTRY"),
            (r"@IBOutlet\s+@\w+\s+", "IB_ACTION"),
            (r"override\s+func\s+viewDidLoad", "LIFECYCLE"),
            (r"\bapplication\s*\([^)]*didFinishLaunchingWithOptions", "LIFECYCLE"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _shell_entry_points(self, source: str, analysis: FileAnalysis):
        patterns = [
            (r"#!/bin/(?:ba)?sh", "MAIN_ENTRY"),
            (r"#!/usr/bin/env\s+(?:ba)?sh", "MAIN_ENTRY"),
            (r"^main\s*\(\s*\)", "MAIN_ENTRY"),
            (r"^\s*function\s+main\s*", "MAIN_ENTRY"),
        ]
        for pattern, ep_type in patterns:
            for m in re.finditer(pattern, source, re.MULTILINE):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

    def _extract_imports(self, node, source: str, analysis: FileAnalysis):
        lang = analysis.language
        parser_obj = self._parsers.get(lang)
        if parser_obj is None:
            self._extract_imports_regex(source, analysis)
            return
        lang_obj = parser_obj.language

        queries = {
            "python": """(import_statement
                    name: (dotted_name) @module)""",
            "javascript": """(import_statement
                    source: (string) @module)""",
            "typescript": """(import_statement
                    source: (string) @module)""",
            "java": """(import_declaration
                    (scoped_identifier) @module)""",
            "c": """(preproc_include
                    path: (string_literal) @module)""",
            "cpp": """(preproc_include
                    path: [(string_literal) @module
                          (system_lib_string) @module])""",
            "go": """(import_declaration
                    (import_spec
                        path: [(interpreted_string_literal) @module
                              (raw_string_literal) @module]))""",
            "rust": """(use_declaration
                    (scoped_identifier) @module)""",
            "csharp": """(using_directive
                    (qualified_name) @module)""",
        }

        query_str = queries.get(lang)
        if not query_str:
            return

        query = _ts_query(lang_obj, query_str)
        if query is None:
            return

        captures = _ts_captures(query, node)
        if not captures:
            return

        for cap_name, cap_nodes in captures.items():
            if cap_name == "module":
                for cap_node in cap_nodes:
                    module_name = source[cap_node.start_byte:cap_node.end_byte].strip("'\"")
                    analysis.imports.append(ImportInfo(
                        file=analysis.path,
                        line=cap_node.start_point[0] + 1,
                        module=module_name,
                    ))

    def _extract_imports_regex(self, source: str, analysis: FileAnalysis):
        patterns = {
            "ruby": [
                (r"require\s+['\"]([^'\"]+)['\"]", "require"),
                (r"require_relative\s+['\"]([^'\"]+)['\"]", "require_relative"),
            ],
            "php": [
                (r"use\s+([\w\\]+)\s*;", "use"),
                (r"require_once\s+['\"]([^'\"]+)['\"]", "require_once"),
                (r"include_once\s+['\"]([^'\"]+)['\"]", "include_once"),
            ],
            "powershell": [
                (r"\.?\s*Import-Module\s+['\"]([^'\"]+)['\"]", "import_module"),
                (r"\.?\s*[\./][^\s]+\.psm1", "dot_source"),
            ],
            "swift": [
                (r"import\s+(\w+)", "import"),
            ],
            "shell": [
                (r"source\s+([^\s]+)", "source"),
                (r"\.\s+([^\s]+)", "dot_source"),
            ],
            "kotlin": [
                (r"import\s+([\w.]+)", "import"),
            ],
        }

        lang_patterns = patterns.get(analysis.language, [])
        for pattern, kind in lang_patterns:
            for m in re.finditer(pattern, source):
                module = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                analysis.imports.append(ImportInfo(
                    file=analysis.path,
                    line=source[:m.start()].count("\n") + 1,
                    module=module,
                ))

    def _extract_classes(self, node, source: str, analysis: FileAnalysis):
        lang = analysis.language
        parser_obj = self._parsers.get(lang)
        if parser_obj is None:
            self._extract_classes_regex(source, analysis)
            return
        lang_obj = parser_obj.language

        queries = {
            "python": "(class_definition name: (identifier) @name)",
            "javascript": "(class_declaration name: (identifier) @name)",
            "typescript": "(class_declaration name: (type_identifier) @name)",
            "java": "(class_declaration name: (identifier) @name)",
            "cpp": "(class_specifier name: (type_identifier) @name)",
            "rust": "(struct_item name: (type_identifier) @name)",
            "go": "(type_declaration (type_spec name: (type_identifier) @name))",
            "csharp": "(class_declaration name: (identifier) @name)",
        }

        query_str = queries.get(lang)
        if not query_str:
            return

        query = _ts_query(lang_obj, query_str)
        if query is None:
            return

        captures = _ts_captures(query, node)
        if not captures:
            return

        for cap_name, cap_nodes in captures.items():
            if cap_name == "name":
                for cap_node in cap_nodes:
                    class_name = source[cap_node.start_byte:cap_node.end_byte]
                    parent = cap_node.parent
                    start_line = cap_node.start_point[0] + 1
                    end_line = parent.end_point[0] + 1 if parent else start_line + 10
                    superclass = ""
                    if parent:
                        for child in parent.children:
                            if child.type in ("superclass", "super_interfaces", "argument_list"):
                                superclass = source[child.start_byte:child.end_byte]
                                break
                    analysis.class_definitions.append(ClassDef(
                        name=class_name, file=analysis.path,
                        line=start_line, end_line=end_line,
                        superclass=superclass,
                    ))

    def _extract_classes_regex(self, source: str, analysis: FileAnalysis):
        patterns = [
            r"class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w\s,]+))?",
            r"module\s+(\w+)",
            r"struct\s+(\w+)",
            r"enum\s+(\w+)",
            r"protocol\s+(\w+)",
        ]
        source_lines = source.split("\n")
        for pattern in patterns:
            for m in re.finditer(pattern, source):
                class_name = m.group(1)
                superclass = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                line = source[:m.start()].count("\n") + 1
                line_idx = line - 1
                end_line = self._find_block_end(source_lines, line_idx, analysis.language)
                analysis.class_definitions.append(ClassDef(
                    name=class_name, file=analysis.path,
                    line=line, end_line=end_line,
                    superclass=superclass or "",
                ))

    def _extract_variables(self, node, source: str, analysis: FileAnalysis):
        lang = analysis.language
        parser_obj = self._parsers.get(lang)
        if parser_obj is None:
            return
        lang_obj = parser_obj.language

        queries = {
            "python": """(assignment
                    left: (identifier) @name)""",
            "javascript": """(variable_declarator
                    name: (identifier) @name)""",
            "typescript": """(variable_declarator
                    name: (identifier) @name)""",
            "java": """(variable_declarator
                    name: (identifier) @name)""",
            "c": """(init_declarator
                    declarator: (identifier) @name)""",
            "cpp": """(init_declarator
                    declarator: (identifier) @name)""",
            "go": """(short_var_declaration
                    left: (expression_list
                        (identifier) @name))""",
            "rust": """(let_declaration
                    pattern: (identifier) @name)""",
            "csharp": """(variable_declarator
                    name: (identifier) @name)""",
        }

        query_str = queries.get(lang)
        if not query_str:
            return

        query = _ts_query(lang_obj, query_str)
        if query is None:
            return

        captures = _ts_captures(query, node)
        if not captures:
            return

        for cap_name, cap_nodes in captures.items():
            if cap_name == "name":
                for cap_node in cap_nodes:
                    var_name = source[cap_node.start_byte:cap_node.end_byte]
                    if len(var_name) > 100:
                        continue
                    analysis.variables.append(Variable(
                        name=var_name,
                        file=analysis.path,
                        line=cap_node.start_point[0] + 1,
                    ))

    def _extract_argument_names(self, args_text: str, lang: str) -> list[str]:
        """Extract variable/identifier names from a call-site argument list."""

        args_text = args_text.strip()
        if not args_text:
            return []

        stripped = args_text[1:-1].strip() if args_text.startswith("(") and args_text.endswith(")") else args_text
        if not stripped:
            return []

        parts = []
        depth = 0
        current = ""
        string_char = ""
        for ch in stripped:
            if string_char:
                current += ch
                if ch == string_char and current[-2:-1] != "\\":
                    string_char = ""
                    current = ""
                continue
            if ch in "\"'":
                string_char = ch
                current += ch
                continue
            if ch in "([{":
                depth += 1
                current += ch
            elif ch in ")]}":
                depth -= 1
                current += ch
            elif ch == "," and depth == 0:
                parts.append(current.strip())
                current = ""
            else:
                current += ch
        if current.strip():
            parts.append(current.strip())

        names = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if lang in ("python",):
                var_match = re.match(r"^(\w+)", p)
                if var_match:
                    names.append(var_match.group(1))
            elif lang in ("javascript", "typescript", "java", "c", "cpp", "csharp"):
                tokens = re.findall(r"\b[a-zA-Z_]\w*\b", p)
                if tokens and not p.startswith(("'", '"', "new ")):
                    names.extend([t for t in tokens if t not in ("new", "return", "this", "super", "true", "false", "null")])
            else:
                var_match = re.match(r"^(\w+)", p)
                if var_match:
                    names.append(var_match.group(1))

        return names

    def _regex_find(self, text: str, pattern: str) -> list[tuple[int, int]]:
        return [(m.start(), m.end()) for m in re.finditer(pattern, text)]

    def _find_block_end(self, source_lines: list[str], start_line_idx: int,
                         language: str = "") -> int:
        """Find the line where a code block ends by tracking brace/end depth.
        
        For brace-based languages ({...}): tracks curly brace depth from the
        start line until a matching closing brace is found.
        For Ruby (def...end): tracks `do`/`{` → `end`/`}` matching.
        Falls back to start + 200 if no clear block delimiter is found.
        """
        total = len(source_lines)
        
        for li in range(start_line_idx, min(start_line_idx + 3, total)):
            line = source_lines[li]
            if '{' in line:
                depth = 0
                for li2 in range(li, total):
                    for ch in source_lines[li2]:
                        if ch == '{':
                            depth += 1
                        elif ch == '}':
                            depth -= 1
                            if depth == 0:
                                return li2 + 1
                return min(start_line_idx + 200, total)
        
        if language == "ruby":
            for li in range(start_line_idx, total):
                stripped = source_lines[li].strip()
                if re.match(r'\bend\b', stripped):
                    return li + 1
            return min(start_line_idx + 200, total)
        
        if language in ("scala",):
            return min(start_line_idx + 20, total)
        
        return min(start_line_idx + 200, total)

    def _parse_with_regex(self, source: str, path: str, language: str) -> FileAnalysis:
        analysis = FileAnalysis(path=path, language=language, lines=source.count("\n"), raw_source=source)

        lang_func_patterns = {
            "ruby": [
                r"(?:def|proc)\s+(\w+(?:\.\w+)*)\s*(?:\(|\s|$)",
            ],
            "php": [
                r"function\s+(\w+)\s*\(",
                r"public\s+function\s+(\w+)\s*\(",
                r"private\s+function\s+(\w+)\s*\(",
                r"protected\s+function\s+(\w+)\s*\(",
            ],
            "powershell": [
                r"(?:function|filter|workflow)\s+([\w-]+)\s*(?:\{|$)",
                r"class\s+(\w+)\s*\{",
            ],
            "swift": [
                r"func\s+(\w+)\s*\(",
                r"class\s+func\s+(\w+)\s*\(",
            ],
            "shell": [
                r"(\w+)\s*\(\)\s*\{",
                r"function\s+(\w+)\s*(?:\{|$)",
            ],
            "kotlin": [
                r"fun\s+(\w+)\s*\(",
                r"suspend\s+fun\s+(\w+)\s*\(",
                r"private\s+fun\s+(\w+)\s*\(",
                r"public\s+fun\s+(\w+)\s*\(",
                r"protected\s+fun\s+(\w+)\s*\(",
                r"internal\s+fun\s+(\w+)\s*\(",
            ],
            "scala": [
                r"def\s+(\w+)\s*\(",
                r"private\s+def\s+(\w+)\s*\(",
                r"public\s+def\s+(\w+)\s*\(",
                r"protected\s+def\s+(\w+)\s*\(",
            ],
        }

        source_lines = source.split("\n")
        func_patterns = lang_func_patterns.get(language, [])
        for pattern in func_patterns:
            for m in re.finditer(pattern, source):
                func_name = m.group(1)
                line = source[:m.start()].count("\n") + 1
                line_idx = line - 1
                end_line = self._find_block_end(source_lines, line_idx, language)
                analysis.functions.append(FunctionDef(
                    name=func_name, file=path, line=line, end_line=end_line,
                ))

        self._extract_imports_regex(source, analysis)
        self._extract_classes_regex(source, analysis)

        ep_patterns = {
            "ruby": [
                (r"(get|post|put|delete|patch)\s+['\"]/", "HTTP_ROUTE"),
                (r"Rack::Builder", "RACK_SERVER"),
            ],
            "php": [
                (r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)", "HTTP_REQUEST"),
            ],
            "powershell": [
                (r"function\s+\w+-\w+", "CMDLET"),
                (r"\bparam\s*\(", "PARAM_BLOCK"),
                (r"\bBegin\s*\{", "BEGIN_BLOCK"),
                (r"\bProcess\s*\{", "PROCESS_BLOCK"),
                (r"\bEnd\s*\{", "END_BLOCK"),
                (r"\bDynamicParam\s*\{", "DYNAMIC_PARAM"),
            ],
            "swift": [
                (r"func\s+main\s*\(", "MAIN_ENTRY"),
                (r"@\w+Server", "SERVER"),
            ],
            "shell": [
                (r"#!/bin/(?:ba)?sh", "MAIN_ENTRY"),
            ],
            "kotlin": [
                (r"fun\s+main\s*\(", "MAIN_ENTRY"),
                (r"\b@GetMapping\b|\bPostMapping\b", "HTTP_ROUTE"),
            ],
        }

        for pattern, ep_type in ep_patterns.get(language, []):
            for m in re.finditer(pattern, source):
                line = source[:m.start()].count("\n") + 1
                analysis.entry_points.append(EntryPoint(
                    file=analysis.path, line=line, type=ep_type,
                    name=f"ep_{line}", description=f"{ep_type} entry point",
                ))

        call_patterns = [
            (r"\b(\w+)\s*\(", "call"),
        ]
        for pattern, kind in call_patterns:
            for m in re.finditer(pattern, source):
                func_name = m.group(1)
                line = source[:m.start()].count("\n") + 1
                analysis.call_sites.append(CallSite(
                    file=analysis.path, line=line, function_name=func_name,
                ))

        analysis.raw_source = source
        return analysis
