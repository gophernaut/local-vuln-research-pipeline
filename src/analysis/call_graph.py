"""Call graph extraction with cross-file import resolution.

Builds inter-procedural call graph from AST analysis.
Resolves imports to find cross-file call edges.
Provides: callers, callees, reachability, path finding.
"""
from __future__ import annotations

import os
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.ast_parser import ASTParser, FileAnalysis, FunctionDef, CallSite, ImportInfo
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class CallGraph:
    nodes: dict[str, FunctionDef] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    reverse_edges: dict[str, set[str]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    file_analyses: list[FileAnalysis] = field(default_factory=list)
    import_map: dict[str, str] = field(default_factory=dict)
    class_methods: dict[str, dict[str, str]] = field(default_factory=dict)
    _func_name_index: dict[str, list[str]] = field(default_factory=dict)

    def add_function(self, func: FunctionDef):
        key = self._func_key(func)
        self.nodes[key] = func
        if func.name not in self._func_name_index:
            self._func_name_index[func.name] = []
        self._func_name_index[func.name].append(key)
        if func.class_name:
            cls_key = f"{func.class_name}.{func.name}"
            if cls_key not in self._func_name_index:
                self._func_name_index[cls_key] = []
            self._func_name_index[cls_key].append(key)

    def add_call_edge(self, caller: str, callee: str):
        if caller not in self.edges:
            self.edges[caller] = set()
        self.edges[caller].add(callee)
        if callee not in self.reverse_edges:
            self.reverse_edges[callee] = set()
        self.reverse_edges[callee].add(caller)

    def get_callers(self, func_key: str) -> set[str]:
        return self.reverse_edges.get(func_key, set())

    def get_callees(self, func_key: str) -> set[str]:
        return self.edges.get(func_key, set())

    def is_reachable_from_entry(self, func_key: str, max_depth: int = 50) -> bool:
        visited: set[str] = set()
        queue = deque(self.entry_points)
        depth = 0
        while queue:
            if depth > max_depth:
                break
            next_queue = deque()
            while queue:
                current = queue.popleft()
                if current == func_key:
                    return True
                if current in visited:
                    continue
                visited.add(current)
                for callee in self.edges.get(current, set()):
                    next_queue.append(callee)
            queue = next_queue
            depth += 1
        return False

    def find_all_paths(
        self, source_key: str, target_key: str, max_depth: int = 8, max_paths: int = 50
    ) -> list[list[str]]:
        paths = []
        queue: deque[tuple[str, list[str]]] = deque([(source_key, [source_key])])
        visited_paths: set[str] = set()

        while queue and len(paths) < max_paths:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            if current == target_key:
                paths.append(path)
                continue
            for callee in sorted(self.edges.get(current, set())):
                path_key = f"{current}->{callee}"
                if path_key not in visited_paths and callee not in path:
                    visited_paths.add(path_key)
                    queue.append((callee, path + [callee]))

        return paths

    def transitive_callees(self, func_key: str, max_depth: int = 10) -> set[str]:
        visited: set[str] = set()
        queue: deque[str] = deque([func_key])
        depth = 0
        while queue and depth < max_depth:
            next_queue = deque()
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                for callee in self.edges.get(current, set()):
                    next_queue.append(callee)
            queue = next_queue
            depth += 1
        visited.discard(func_key)
        return visited

    def functions_in_file(self, filepath: str) -> list[str]:
        keys = []
        for key, func in self.nodes.items():
            if func.file == filepath:
                keys.append(key)
        return sorted(keys)

    def functions_by_class(self, class_name: str) -> list[str]:
        keys = []
        for key, func in self.nodes.items():
            if func.class_name == class_name:
                keys.append(key)
        return sorted(keys)

    @staticmethod
    def _func_key(func: FunctionDef) -> str:
        return f"{func.file}::{func.name}"


class CallGraphBuilder:
    def __init__(self):
        self.parser = ASTParser()

    def build(self, repo_path: Path) -> CallGraph:
        analyses = self.parser.parse_directory(repo_path)
        graph = CallGraph(file_analyses=analyses)

        for analysis in analyses:
            for func in analysis.functions:
                graph.add_function(func)
                if analysis.entry_points:
                    for ep in analysis.entry_points:
                        key = CallGraph._func_key(func)
                        if ep.type in ("MAIN_ENTRY", "HTTP_ROUTE", "SERVER_LISTEN",
                                       "DLL_ENTRY", "IOCTL_HANDLER", "SYSCALL",
                                       "EXPORTED_FUNC", "FFI_EXPORT", "CMDLET"):
                            if ep.line <= func.end_line and ep.line >= func.line - 5:
                                graph.entry_points.append(key)
                                break

        self._resolve_imports(graph, repo_path)
        self._build_edges(graph)
        self._resolve_method_calls(graph)

        entry_set = set(graph.entry_points)
        for ep_key in list(graph.entry_points):
            callees = graph.edges.get(ep_key, set())
            for callee in callees:
                if callee not in entry_set:
                    graph.entry_points.append(callee)

        logger.info(
            f"Call graph: {len(graph.nodes)} functions, "
            f"{sum(len(e) for e in graph.edges.values())} edges, "
            f"{len(graph.entry_points)} entry points"
        )
        return graph

    def _resolve_imports(self, graph: CallGraph, repo_path: Path):
        file_to_analysis = {}
        for analysis in graph.file_analyses:
            file_to_analysis[analysis.path] = analysis

        module_to_files: dict[str, list[str]] = {}
        for analysis in graph.file_analyses:
            for imp in analysis.imports:
                module = imp.module
                module_to_files.setdefault(module, []).append(analysis.path)

        for analysis in graph.file_analyses:
            for imp in analysis.imports:
                module = imp.module
                target_files = module_to_files.get(module, [])
                for target_file in target_files:
                    rel_target = target_file
                    rel_source = analysis.path
                    graph.import_map[f"{rel_source}:{module}"] = rel_target

            for imp in analysis.imports:
                module = imp.module
                for target_file in module_to_files.get(module, []):
                    target_analysis = file_to_analysis.get(target_file)
                    if not target_analysis:
                        continue
                    for target_func in target_analysis.functions:
                        if target_func.is_exported or not target_func.name.startswith("_"):
                            graph.import_map[f"{analysis.path}:{imp.module}:{target_func.name}"] = CallGraph._func_key(target_func)

        for filepath, ext in [
            (f, Path(f).suffix) for f in [a.path for a in graph.file_analyses]
        ]:
            if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs"):
                self._resolve_js_exports(graph, file_to_analysis.get(filepath), file_to_analysis, repo_path)
            elif ext == ".py":
                self._resolve_python_from_import(graph, file_to_analysis.get(filepath), file_to_analysis, repo_path)

    def _resolve_js_exports(self, graph: CallGraph, analysis: FileAnalysis | None,
                            all_analyses: dict[str, FileAnalysis], repo_path: Path):
        if not analysis:
            return
        try:
            with open(analysis.path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return

        export_patterns = [
            r"module\.exports\s*=\s*\{([^}]+)\}",
            r"export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)",
            r"export\s+\{([^}]+)\}",
        ]
        for pattern in export_patterns:
            for m in re.finditer(pattern, source):
                exported = m.group(1) if m.lastindex else ""
                for name in re.findall(r"\w+", exported):
                    key = f"{analysis.path}::{name}"
                    if key in graph.nodes:
                        graph.nodes[key].is_exported = True

    def _resolve_python_from_import(self, graph: CallGraph, analysis: FileAnalysis | None,
                                     all_analyses: dict[str, FileAnalysis], repo_path: Path):
        if not analysis:
            return
        for imp in analysis.imports:
            if imp.module:
                target_key = f"{analysis.path}:{imp.module}"
                target_file = graph.import_map.get(target_key)
                if target_file:
                    target_analysis = all_analyses.get(target_file)
                    if target_analysis:
                        for func in target_analysis.functions:
                            key = CallGraph._func_key(func)
                            if func.name in [a for a in (imp.imported_names or [])]:
                                graph.import_map[f"{analysis.path}:{func.name}"] = key

    def _build_edges(self, graph: CallGraph):
        for analysis in graph.file_analyses:
            caller_map: dict[int, str] = {}
            for func in analysis.functions:
                for line in range(func.line, func.end_line + 1):
                    caller_map[line] = CallGraph._func_key(func)

            for call in analysis.call_sites:
                caller_key = caller_map.get(call.line, "")
                if not caller_key:
                    continue

                func_index = graph._func_name_index
                if call.function_name in func_index:
                    for callee_key in func_index[call.function_name]:
                        graph.add_call_edge(caller_key, callee_key)

                obj_key = f"{analysis.path}:{call.function_name}"
                if obj_key in graph._func_name_index:
                    for callee_key in graph._func_name_index[obj_key]:
                        graph.add_call_edge(caller_key, callee_key)

    def _resolve_method_calls(self, graph: CallGraph):
        for analysis in graph.file_analyses:
            caller_map: dict[int, str] = {}
            for func in analysis.functions:
                for line in range(func.line, func.end_line + 1):
                    caller_map[line] = CallGraph._func_key(func)

            for call in analysis.call_sites:
                caller_key = caller_map.get(call.line, "")
                if not caller_key:
                    continue

                if call.object_name:
                    for cls_key, methods in graph.class_methods.items():
                        if call.function_name in methods:
                            graph.add_call_edge(caller_key, methods[call.function_name])
