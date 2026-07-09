"""Call graph extraction — builds inter-procedural call graph from AST analysis.

Key functions: who calls whom, which functions are reachable from entry points.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.ast_parser import ASTParser, FileAnalysis, FunctionDef, CallSite
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class CallGraph:
    nodes: dict[str, list[FunctionDef]] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    reverse_edges: dict[str, set[str]] = field(default_factory=dict)
    entry_points: dict[str, list[str]] = field(default_factory=dict)
    file_analyses: list[FileAnalysis] = field(default_factory=list)

    def add_function(self, func: FunctionDef):
        key = self._func_key(func)
        if key not in self.nodes:
            self.nodes[key] = []
        self.nodes[key].append(func)

    def add_call_edge(self, caller: str, callee: str):
        if caller not in self.edges:
            self.edges[caller] = set()
        self.edges[caller].add(callee)

        if callee not in self.reverse_edges:
            self.reverse_edges[callee] = set()
        self.reverse_edges[callee].add(caller)

    def get_callers(self, func_name: str) -> set[str]:
        return self.reverse_edges.get(func_name, set())

    def get_callees(self, func_name: str) -> set[str]:
        return self.edges.get(func_name, set())

    def is_reachable_from_entry(self, func_name: str) -> bool:
        visited: set[str] = set()
        stack = list(self.entry_points.get("all", []))
        while stack:
            current = stack.pop()
            if current == func_name:
                return True
            if current in visited:
                continue
            visited.add(current)
            stack.extend(self.edges.get(current, set()))
        return False

    def path_from_entry(self, target_func: str) -> list[list[str]] | None:
        paths = []
        for entry in self.entry_points.get("all", []):
            p = self._find_path(entry, target_func)
            if p:
                paths.append(p)
        return paths if paths else None

    def _find_path(self, start: str, target: str, max_depth: int = 10) -> list[str] | None:
        from collections import deque
        parent: dict[str, str] = {}
        queue = deque([start])
        visited = {start}

        while queue:
            current = queue.popleft()
            if current == target:
                path = [current]
                while path[-1] != start:
                    path.append(parent[path[-1]])
                return path[::-1]

            for callee in self.edges.get(current, set()):
                if callee not in visited:
                    visited.add(callee)
                    parent[callee] = current
                    queue.append(callee)

            if len(visited) > max_depth * 100:
                break

        return None

    @staticmethod
    def _func_key(func: FunctionDef) -> str:
        return f"{func.file}:{func.name}"


class CallGraphBuilder:
    def __init__(self):
        self.parser = ASTParser()

    def build(self, repo_path: Path) -> CallGraph:
        analyses = self.parser.parse_directory(repo_path)
        graph = CallGraph(file_analyses=analyses)

        func_index: dict[str, list[str]] = {}

        for analysis in analyses:
            for func in analysis.functions:
                graph.add_function(func)
                key = graph._func_key(func)
                if func.name not in func_index:
                    func_index[func.name] = []
                func_index[func.name].append(key)

            for entry in analysis.entry_points:
                if "all" not in graph.entry_points:
                    graph.entry_points["all"] = []
                graph.entry_points["all"].append(
                    f"{entry.file}:{entry.name}"
                )

        for analysis in analyses:
            for call_site in analysis.call_sites:
                caller_candidates = [
                    f for f in analysis.functions
                    if f.line <= call_site.line <= f.end_line
                ]
                caller_key = caller_candidates[-1].name if caller_candidates else "unknown"
                caller_full = f"{analysis.path}:{caller_key}"

                if call_site.function_name in func_index:
                    for callee_key in func_index[call_site.function_name]:
                        graph.add_call_edge(caller_full, callee_key)

        logger.info(
            f"Call graph built: {len(graph.nodes)} functions, "
            f"{sum(len(e) for e in graph.edges.values())} edges"
        )
        return graph
