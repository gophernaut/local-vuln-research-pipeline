"""Multi-language AST parser using tree-sitter.

Extracts: functions, classes, method calls, imports, string literals,
assignments, and entry points per language.

Gracefully degrades if tree-sitter language packages are not installed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LANGUAGE_PARSERS: dict[str, Any] = {}
TREE_SITTER_AVAILABLE = False
TREE_SITTER_PARSER: Any = None

try:
    from tree_sitter import Parser as TSParser, Language
    TREE_SITTER_AVAILABLE = True
    TREE_SITTER_PARSER = TSParser
except ImportError:
    pass

if TREE_SITTER_AVAILABLE:
    try:
        import tree_sitter_python as tspy
        LANGUAGE_PARSERS["python"] = tspy.language()
    except (ImportError, AttributeError):
        pass

    try:
        import tree_sitter_javascript as tsjs
        LANGUAGE_PARSERS["javascript"] = tsjs.language()
    except (ImportError, AttributeError):
        pass

    try:
        import tree_sitter_typescript as tsts
        try:
            LANGUAGE_PARSERS["typescript"] = tsts.language_tsx()
        except AttributeError:
            pass
    except ImportError:
        pass


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
}

LANG_TO_EXT = {v: k for k, v in LANGUAGE_EXTENSIONS.items()}


@dataclass
class FunctionDef:
    name: str
    file: str
    line: int
    end_line: int
    params: list[str] = field(default_factory=list)
    body: str = ""
    is_exported: bool = False


@dataclass
class CallSite:
    file: str
    line: int
    function_name: str
    arguments: list[str] = field(default_factory=list)
    caller_function: str = ""


@dataclass
class EntryPoint:
    file: str
    line: int
    type: str
    name: str
    description: str


@dataclass
class ImportInfo:
    file: str
    line: int
    module: str
    imported_names: list[str] = field(default_factory=list)


@dataclass
class FileAnalysis:
    path: str
    language: str
    functions: list[FunctionDef] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    class_definitions: list[str] = field(default_factory=list)
    lines: int = 0


class ASTParser:
    def __init__(self):
        self._parsers: dict[str, Any] = {}
        if TREE_SITTER_AVAILABLE:
            self._init_available_parsers()

    def _init_available_parsers(self):
        for lang, lang_obj in LANGUAGE_PARSERS.items():
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

        if language not in self._parsers:
            return None

        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return None

        relative_path = str(filepath)

        parser = self._parsers[language]
        tree = parser.parse(source.encode("utf-8"))

        analysis = FileAnalysis(
            path=relative_path,
            language=language,
            lines=source.count("\n"),
        )

        self._extract_functions(tree.root_node, source, analysis)
        self._extract_call_sites(tree.root_node, source, analysis)
        self._extract_entry_points(tree.root_node, source, analysis)
        self._extract_imports(tree.root_node, source, analysis)
        self._extract_classes(tree.root_node, source, analysis)

        return analysis

    def parse_directory(self, repo_path: Path) -> list[FileAnalysis]:
        results = []
        files = []
        for ext in LANGUAGE_EXTENSIONS:
            files.extend(repo_path.rglob(f"*{ext}"))

        for filepath in files:
            analysis = self.parse_file(filepath)
            if analysis:
                results.append(analysis)

        return results

    def _extract_functions(self, node, source: str, analysis: FileAnalysis):
        query = None
        lang = analysis.language

        try:
            query_lang = self._parsers[lang].language
            if lang in ("python",):
                query = query_lang.query("""
                    (function_definition
                        name: (identifier) @name
                        parameters: (parameters) @params
                        body: (block) @body) @func
                """)
            elif lang in ("javascript", "typescript"):
                query = query_lang.query("""
                    (function_declaration
                        name: (identifier) @name
                        parameters: (formal_parameters) @params
                        body: (statement_block) @body) @func
                """)

            if query is None:
                return

            captures = query.captures(node)
            func_nodes = {}
            for cap_node, cap_name in captures:
                if cap_name == "func":
                    func_nodes[cap_node.id] = {"node": cap_node}
                elif cap_name == "name":
                    parent_id = cap_node.parent.id if cap_node.parent else None
                    if parent_id in func_nodes:
                        func_nodes[parent_id]["name"] = source[cap_node.start_byte:cap_node.end_byte]
                elif cap_name == "body":
                    for fid, fdata in list(func_nodes.items()):
                        if cap_node.start_byte >= fdata["node"].start_byte and cap_node.end_byte <= fdata["node"].end_byte:
                            func_nodes[fid]["body"] = source[cap_node.start_byte:cap_node.end_byte]
                            func_nodes[fid]["end_line"] = cap_node.end_point[0] + 1

            for fid, fdata in func_nodes.items():
                if "name" in fdata:
                    analysis.functions.append(FunctionDef(
                        name=fdata["name"],
                        file=analysis.path,
                        line=fdata["node"].start_point[0] + 1,
                        end_line=fdata.get("end_line", fdata["node"].end_point[0] + 1),
                        body=fdata.get("body", ""),
                    ))
        except Exception:
            pass

    def _extract_call_sites(self, node, source: str, analysis: FileAnalysis):
        try:
            lang = analysis.language
            query_lang = self._parsers[lang].language

            if lang in ("python",):
                query = query_lang.query("""
                    (call
                        function: (identifier) @func_name
                        arguments: (argument_list) @args) @call
                """)
            elif lang in ("javascript", "typescript"):
                query = query_lang.query("""
                    (call_expression
                        function: (identifier) @func_name
                        arguments: (arguments) @args) @call
                """)
            else:
                return

            captures = query.captures(node)
            for cap_node, cap_name in captures:
                if cap_name == "func_name":
                    func_name = source[cap_node.start_byte:cap_node.end_byte]
                    analysis.call_sites.append(CallSite(
                        file=analysis.path,
                        line=cap_node.start_point[0] + 1,
                        function_name=func_name,
                    ))
        except Exception:
            pass

    def _extract_entry_points(self, node, source: str, analysis: FileAnalysis):
        lang = analysis.language

        if lang in ("python",):
            # Flask/FastAPI/Django route decorators
            route_patterns = [
                r"@app\.(route|get|post|put|delete|patch)\(",
                r"@router\.(get|post|put|delete|patch)\(",
                r"@blueprint\.route\(",
                r"@api\.(get|post|put|delete)\(",
            ]
            for pattern in route_patterns:
                for match in self._regex_find(source, pattern):
                    line = source[:match[0]].count("\n") + 1
                    analysis.entry_points.append(EntryPoint(
                        file=analysis.path, line=line, type="HTTP_ROUTE",
                        name=f"decorator@{line}", description="HTTP route handler",
                    ))

        elif lang in ("javascript", "typescript"):
            route_patterns = [
                r"app\.(get|post|put|delete|patch|use)\(",
                r"router\.(get|post|put|delete|patch|use)\(",
            ]
            for pattern in route_patterns:
                for match in self._regex_find(source, pattern):
                    line = source[:match[0]].count("\n") + 1
                    analysis.entry_points.append(EntryPoint(
                        file=analysis.path, line=line, type="HTTP_ROUTE",
                        name=f"express@{line}", description="Express route handler",
                    ))

    def _extract_imports(self, node, source: str, analysis: FileAnalysis):
        try:
            lang = analysis.language
            query_lang = self._parsers[lang].language

            if lang in ("python",):
                query = query_lang.query("""
                    (import_statement name: (dotted_name) @module) @import
                    (import_from_statement module_name: (dotted_name) @module name: (dotted_name) @alias) @import
                """)
            elif lang in ("javascript", "typescript"):
                query = query_lang.query("""
                    (import_statement source: (string) @module) @import
                """)
            else:
                return

            captures = query.captures(node)
            for cap_node, cap_name in captures:
                if cap_name == "module":
                    module_name = source[cap_node.start_byte:cap_node.end_byte].strip("'\"")
                    analysis.imports.append(ImportInfo(
                        file=analysis.path,
                        line=cap_node.start_point[0] + 1,
                        module=module_name,
                    ))
        except Exception:
            pass

    def _extract_classes(self, node, source: str, analysis: FileAnalysis):
        try:
            lang = analysis.language
            query_lang = self._parsers[lang].language

            if lang in ("python",):
                query = query_lang.query("""
                    (class_definition name: (identifier) @name) @class
                """)
            elif lang in ("javascript", "typescript"):
                query = query_lang.query("""
                    (class_declaration name: (identifier) @name) @class
                """)
            else:
                return

            captures = query.captures(node)
            for cap_node, cap_name in captures:
                if cap_name == "name":
                    analysis.class_definitions.append(
                        source[cap_node.start_byte:cap_node.end_byte]
                    )
        except Exception:
            pass

    def _regex_find(self, text: str, pattern: str) -> list[tuple[int, int]]:
        import re
        return [(m.start(), m.end()) for m in re.finditer(pattern, text)]
