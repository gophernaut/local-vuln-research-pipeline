"""Path enumeration engine — enumerates ALL source-to-sink paths through call graph.

For every (source, sink) pair that is compatible:
1. Use the call graph to find all call paths from source to sink
2. Trace taint through each function on the path
3. Identify which paths have effective sanitizers
4. Output the complete path inventory

This is the core of the system — it ensures no source-to-sink path is missed.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.call_graph import CallGraph
from src.analysis.intra_taint import IntraTaintTracker, trace_function_fully
from src.analysis.inter_taint import InterTaintPropagator
from src.analysis.sink_tag import SinkTag
from src.analysis.source_tag import SourceTag
from src.analysis.sanitizer_tag import SanitizerTag
from src.analysis.ast_parser import FileAnalysis, FunctionDef
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class PathStep:
    function_key: str
    file: str
    line: int
    function_name: str
    tainted_vars: set[str] = field(default_factory=set)
    sink_reach: dict | None = None
    sanitizer_seen: list[str] = field(default_factory=list)


@dataclass
class ExploitPath:
    path_id: str
    source: SourceTag
    sink: SinkTag
    steps: list[PathStep] = field(default_factory=list)
    reachable: bool = True
    is_exploitable: bool = False
    is_blocked_by_sanitizer: bool = False
    sanitizers_on_path: list[SanitizerTag] = field(default_factory=list)
    cwe_id: str = ""
    confidence: float = 0.0
    notes: str = ""


SINK_TO_SANITIZER_TAXONOMY = {
    "command_execution": ["command_injection", "code_execution"],
    "sql_injection": ["sql_injection"],
    "ssrf": ["ssrf", "url_manipulation"],
    "path_traversal": ["path_traversal", "file_inclusion"],
    "deserialization": ["deserialization", "code_execution"],
    "template_injection": ["template_injection", "code_execution"],
    "xxe": ["xxe"],
    "code_execution": ["command_injection", "code_execution"],
    "code_injection": ["command_injection", "code_execution"],
    "file_write": ["path_traversal", "file_inclusion"],
    "file_read": ["path_traversal", "file_inclusion"],
    "file_inclusion": ["file_inclusion", "code_execution"],
    "ldap_injection": ["ldap_injection"],
    "xpath_injection": ["xpath_injection"],
    "nosql_injection": ["nosql_injection"],
    "spel_injection": ["spel_injection"],
    "reflection_invoke": ["command_injection", "code_execution"],
    "buffer_overflow": ["buffer_overflow"],
    "format_string": ["format_string"],
    "auth_bypass": ["auth_bypass", "privilege_escalation"],
    "hardcoded_secret": ["auth_bypass"],
    "weak_crypto": ["weak_crypto"],
    "weak_random": ["weak_random"],
    "race_condition": ["race_condition"],
    "toctou": ["toctou"],
    "security_misconfig": ["security_misconfig"],
    "object_injection": ["deserialization", "object_injection"],
    "xss": ["xss", "html_injection"],
    "html_injection": ["xss", "html_injection"],
    "csrf": ["csrf"],
    "type_confusion": ["type_confusion"],
    "integer_overflow": ["buffer_overflow"],
    "transmute": ["buffer_overflow", "memory_corruption"],
    "yaml_deserialize": ["deserialization"],
}


SOURCE_SINK_COMPATIBILITY = {
    "HTTP_REQUEST": ["command_execution", "sql_injection", "ssrf", "path_traversal",
                     "deserialization", "template_injection", "xxe", "code_execution",
                     "file_write", "file_read", "ldap_injection", "xpath_injection",
                     "nosql_injection", "spel_injection", "reflection_invoke",
                     "buffer_overflow", "race_condition", "format_string",
                     "auth_bypass", "hardcoded_secret", "weak_crypto", "weak_random",
                     "race_condition", "toctou", "security_misconfig",
                     "object_injection", "code_injection"],
    "HTTP_BODY": ["command_execution", "sql_injection", "ssrf", "path_traversal",
                  "deserialization", "code_execution", "file_write",
                  "auth_bypass", "hardcoded_secret", "weak_crypto"],
    "HTTP_PARAM": ["command_execution", "sql_injection", "ssrf", "path_traversal",
                   "deserialization", "code_execution", "ldap_injection", "xpath_injection",
                   "auth_bypass", "hardcoded_secret", "weak_crypto", "weak_random",
                   "security_misconfig", "race_condition", "xxe"],
    "HTTP_QUERY": ["sql_injection", "command_injection", "path_traversal", "ssrf",
                   "auth_bypass", "hardcoded_secret"],
    "HTTP_FORM": ["command_execution", "sql_injection", "path_traversal", "ssrf",
                  "auth_bypass", "hardcoded_secret"],
    "HTTP_ROUTE": ["command_execution", "sql_injection", "path_traversal", "deserialization",
                   "auth_bypass", "hardcoded_secret", "weak_crypto", "weak_random",
                   "template_injection", "code_execution"],
    "ROUTE_PARAM": ["command_execution", "sql_injection", "ssrf", "path_traversal",
                    "deserialization", "code_execution", "file_write", "auth_bypass",
                    "hardcoded_secret", "weak_crypto", "weak_random", "template_injection",
                    "ldap_injection", "xpath_injection", "nosql_injection", "spel_injection"],
    "HTTP_ROUTE_PARAM": ["command_execution", "sql_injection", "ssrf", "path_traversal",
                         "deserialization", "code_execution", "file_write", "auth_bypass",
                         "hardcoded_secret", "weak_crypto", "weak_random", "template_injection"],
    "CLI_ARG": ["command_execution", "sql_injection", "path_traversal", "code_execution",
                "buffer_overflow", "format_string", "file_inclusion", "file_write",
                "auth_bypass", "hardcoded_secret", "weak_crypto", "weak_random"],
    "ENV_VAR": ["command_execution", "sql_injection", "path_traversal", "code_execution",
                "auth_bypass", "hardcoded_secret", "weak_crypto", "weak_random"],
    "STDIN": ["command_execution", "path_traversal", "buffer_overflow", "format_string",
              "code_execution", "weak_random"],
    "FILE_READ": ["deserialization", "yaml_deserialize", "command_execution", "code_execution",
                  "weak_crypto", "weak_random"],
    "SOCKET_READ": ["buffer_overflow", "command_execution", "deserialization",
                    "weak_random"],
    "DESERIALIZE": ["code_execution", "command_execution", "file_read"],
    "JSON_INPUT": ["command_execution", "ssrf", "sql_injection", "code_execution",
                   "weak_random"],
    "YAML_DESERIALIZE": ["code_execution", "command_execution", "file_read"],
    "KERNEL_USERSPACE": ["buffer_overflow", "format_string", "integer_overflow", "race_condition"],
    "SYSCALL": ["buffer_overflow", "format_string", "integer_overflow", "race_condition"],
    "IOCTL": ["buffer_overflow", "format_string", "integer_overflow"],
    "UNSAFE": ["buffer_overflow", "format_string", "integer_overflow", "transmute"],
    "FFI_API": ["buffer_overflow", "format_string", "integer_overflow"],
    "PS_PARAM": ["command_execution", "code_execution", "deserialization", "path_traversal"],
    "PS_ARGS": ["command_execution", "code_execution", "path_traversal"],
    "PS_STDIN": ["command_execution", "code_execution"],
    "PS_FILE_READ": ["deserialization", "command_execution", "code_execution"],
    "PS_CLIXML_READ": ["deserialization", "code_execution"],
    "PS_JSON_INPUT": ["code_execution", "command_execution"],
    "PS_HTTP_CLIENT": ["ssrf", "command_execution"],
}


class PathEnumerator:
    def __init__(self, max_depth: int = 8, max_paths_per_pair: int = 20):
        self.max_depth = max_depth
        self.max_paths_per_pair = max_paths_per_pair
        self.intra = IntraTaintTracker()
        self.inter = InterTaintPropagator()

    def enumerate_all_paths(
        self,
        call_graph: CallGraph,
        sources: list[SourceTag],
        sinks: list[SinkTag],
        sanitizers: list[SanitizerTag],
        file_analyses: list[FileAnalysis],
    ) -> list[ExploitPath]:
        logger.info(f"Enumerating paths: {len(sources)} sources × {len(sinks)} sinks")

        sources_by_file: dict[str, list[SourceTag]] = defaultdict(list)
        for s in sources:
            sources_by_file[s.file].append(s)

        sinks_by_file: dict[str, list[SinkTag]] = defaultdict(list)
        for s in sinks:
            sinks_by_file[s.file].append(s)

        sanitizers_by_file: dict[str, list[SanitizerTag]] = defaultdict(list)
        for s in sanitizers:
            sanitizers_by_file[s.file].append(s)

        functions_by_file: dict[str, list[FunctionDef]] = defaultdict(list)
        for func in call_graph.nodes.values():
            functions_by_file[func.file].append(func)

        all_paths: list[ExploitPath] = []
        path_id = 0

        for source_file, source_list in sources_by_file.items():
            for source in source_list:
                for sink_file, sink_list in sinks_by_file.items():
                    for sink in sink_list:
                        if not self._is_compatible(source.source_type, sink.category):
                            continue

                        source_func_keys = self._find_functions_at_line_with_decorator(
                            functions_by_file.get(source_file, []), source.line
                        )
                        sink_func_keys = self._find_functions_at_line(
                            functions_by_file.get(sink_file, []), sink.line
                        )

                        for source_key in source_func_keys:
                            for sink_key in sink_func_keys:
                                paths = call_graph.find_all_paths(
                                    source_key, sink_key,
                                    max_depth=self.max_depth,
                                    max_paths=self.max_paths_per_pair,
                                )
                                for path in paths:
                                    exploit_path = self._build_exploit_path(
                                        path_id=path_id,
                                        source=source, sink=sink,
                                        call_path=path, call_graph=call_graph,
                                        sanitizers_by_file=sanitizers_by_file,
                                    )
                                    if exploit_path:
                                        all_paths.append(exploit_path)
                                        path_id += 1

                        if not sink_func_keys and source_func_keys:
                            for source_key in source_func_keys:
                                exploit_path = self._build_exploit_path(
                                    path_id=path_id,
                                    source=source, sink=sink,
                                    call_path=[source_key], call_graph=call_graph,
                                    sanitizers_by_file=sanitizers_by_file,
                                )
                                if exploit_path:
                                    all_paths.append(exploit_path)
                                    path_id += 1

                        if not sink_func_keys:
                            for source_key in source_func_keys:
                                if source_file != sink_file:
                                    continue
                                if sink.category in ("security_misconfig", "race_condition", "hardcoded_secret"):
                                    exploit_path = ExploitPath(
                                        path_id=f"P{path_id}",
                                        source=source, sink=sink,
                                        steps=[PathStep(
                                            function_key=source_key,
                                            file=source.file,
                                            line=0,
                                            function_name=source_key.split("::")[-1],
                                        )],
                                        sanitizers_on_path=[],
                                        cwe_id=sink.cwe_id,
                                        is_exploitable=True,
                                        is_blocked_by_sanitizer=False,
                                    )
                                    all_paths.append(exploit_path)
                                    path_id += 1

        self._add_module_level_sinks(
            all_paths, sources, sinks, sanitizers_by_file,
            functions_by_file, path_id
        )

        logger.info(f"Enumerated {len(all_paths)} source-to-sink paths")
        return all_paths

    def _add_module_level_sinks(
        self, all_paths: list, sources: list, sinks: list,
        sanitizers_by_file: dict, functions_by_file: dict, path_id: int,
    ) -> int:
        module_level_categories = {
            "security_misconfig", "race_condition", "hardcoded_secret",
            "weak_crypto", "weak_random"
        }
        for sink in sinks:
            if sink.category not in module_level_categories:
                continue
            sink_funcs = self._find_functions_at_line(
                functions_by_file.get(sink.file, []), sink.line
            )
            if sink_funcs:
                continue
            for source in sources:
                if source.file != sink.file:
                    continue
                if not self._is_compatible(source.source_type, sink.category):
                    continue
                exploit_path = ExploitPath(
                    path_id=f"P{path_id}",
                    source=source, sink=sink,
                    steps=[PathStep(
                        function_key=f"{sink.file}::__module__",
                        file=sink.file,
                        line=sink.line,
                        function_name="<module-level>",
                    )],
                    sanitizers_on_path=[],
                    cwe_id=sink.cwe_id,
                    is_exploitable=True,
                    is_blocked_by_sanitizer=False,
                )
                all_paths.append(exploit_path)
                path_id += 1
        return path_id

    def _is_compatible(self, source_type: str, sink_category: str) -> bool:
        compatible = SOURCE_SINK_COMPATIBILITY.get(source_type, [])
        if compatible:
            return sink_category in compatible
        return True

    def _find_functions_at_line(self, functions: list[FunctionDef], line: int) -> list[str]:
        keys = []
        for func in functions:
            if func.line <= line <= func.end_line:
                keys.append(f"{func.file}::{func.name}")
        return keys

    def _find_functions_at_line_with_decorator(self, functions: list[FunctionDef], line: int) -> list[str]:
        keys = self._find_functions_at_line(functions, line)
        if not keys:
            for func in functions:
                if line < func.line and (func.line - line) <= 5:
                    keys.append(f"{func.file}::{func.name}")
        return keys

    def _build_exploit_path(
        self, path_id: int, source: SourceTag, sink: SinkTag,
        call_path: list[str], call_graph: CallGraph,
        sanitizers_by_file: dict[str, list[SanitizerTag]],
    ) -> ExploitPath | None:
        steps = []
        sanitizers_on_path = []
        tainted_vars: set[str] = set()
        if source.variable and "." not in source.variable and "(" not in source.variable:
            tainted_vars.add(source.variable)
        if source.source_type:
            tainted_vars.add(source.source_type)

        sink_in_last_func = False
        module_level_sink = not call_path

        for i, func_key in enumerate(call_path):
            func = call_graph.nodes.get(func_key)
            if not func:
                continue

            sanitizers_in_func = [
                s for s in sanitizers_by_file.get(func.file, [])
                if func.line <= s.line <= func.end_line
            ]
            sanitizers_on_path.extend(sanitizers_in_func)

            is_sink_func = func.line <= sink.line <= func.end_line

            param_names = set(func.params) if hasattr(func, 'params') and func.params else set()
            seed_vars = tainted_vars.copy()
            if is_sink_func:
                seed_vars.update({"user", "data", "input", "arg", "param", "value"})
            seed_vars.update(param_names)

            try:
                tstate = self.intra.trace_function(
                    function_body=func.body,
                    function_name=func.name,
                    file=func.file,
                    language=self._language_for_file(func.file),
                    source_tag_vars=seed_vars,
                    param_names=param_names,
                )
            except Exception:
                if is_sink_func:
                    sink_in_last_func = True
                continue

            tainted_vars |= tstate.tainted_vars

            if is_sink_func:
                sink_in_last_func = True

            sink_reach = None
            if is_sink_func:
                for reach in tstate.sink_reaches:
                    reach_line = reach.get("line", 0)
                    if reach_line == sink.line or abs(reach_line - sink.line) <= 1:
                        sink_reach = reach
                        break

            steps.append(PathStep(
                function_key=func_key,
                file=func.file,
                line=func.line,
                function_name=func.name,
                tainted_vars=tainted_vars.copy(),
                sink_reach=sink_reach,
                sanitizer_seen=[s.function_name for s in sanitizers_in_func],
            ))

        if not steps and not module_level_sink:
            return None

        sink_func_has_reach = any(s.sink_reach for s in steps)
        is_blocked = self._is_blocked_by_sanitizer(sanitizers_on_path, sink)

        is_exploitable = True
        if is_blocked:
            is_exploitable = False
        elif sink.category in ("race_condition", "security_misconfig", "toctou"):
            is_exploitable = True
        elif not sink_in_last_func and not module_level_sink:
            is_exploitable = False

        return ExploitPath(
            path_id=f"P{path_id}",
            source=source, sink=sink,
            steps=steps,
            sanitizers_on_path=sanitizers_on_path,
            cwe_id=sink.cwe_id,
            is_exploitable=is_exploitable,
            is_blocked_by_sanitizer=is_blocked,
        )

    def _is_path_exploitable(self, steps: list[PathStep], sanitizers: list[SanitizerTag],
                             sink: SinkTag) -> bool:
        for step in steps:
            if step.sink_reach and not step.sink_reach.get("is_sanitized", False):
                return True
        return False

    def _is_blocked_by_sanitizer(self, sanitizers: list[SanitizerTag],
                                  sink: SinkTag) -> bool:
        if not sanitizers:
            return False
        normalized_categories = SINK_TO_SANITIZER_TAXONOMY.get(sink.category, [sink.category])
        for sanitizer in sanitizers:
            for protected in sanitizer.protected_against:
                if protected in normalized_categories:
                    return True
        return False

    def _language_for_file(self, filepath: str) -> str:
        from src.analysis.ast_parser import LANGUAGE_EXTENSIONS
        ext = Path(filepath).suffix.lower()
        return LANGUAGE_EXTENSIONS.get(ext, "python")


def enumerate_paths(
    call_graph: CallGraph,
    sources: list[SourceTag],
    sinks: list[SinkTag],
    sanitizers: list[SanitizerTag],
    file_analyses: list[FileAnalysis],
    max_depth: int = 8,
    max_paths_per_pair: int = 20,
) -> list[ExploitPath]:
    enumerator = PathEnumerator(max_depth=max_depth, max_paths_per_pair=max_paths_per_pair)
    return enumerator.enumerate_all_paths(call_graph, sources, sinks, sanitizers, file_analyses)
