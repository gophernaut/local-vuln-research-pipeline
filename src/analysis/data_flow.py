"""Data flow / taint analysis — traces user-controlled data through code paths.

Starting from entry points and parameters, tracks how data flows to sinks.
Provides initial intra-file and basic inter-file taint propagation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.ast_parser import ASTParser, FileAnalysis
from src.analysis.sink_finder import SinkMatch, SinkFinder
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class TaintSource:
    file: str
    line: int
    variable: str
    source_type: str
    description: str


@dataclass
class TaintFlow:
    source: TaintSource
    sink: SinkMatch
    path: list[str] = field(default_factory=list)
    confidence: float = 0.0


class DataFlowAnalyzer:
    def __init__(self):
        self.parser = ASTParser()
        self.sink_finder = SinkFinder()

    def analyze(self, repo_path: Path) -> list[TaintFlow]:
        flows: list[TaintFlow] = []
        analyses = self.parser.parse_directory(repo_path)

        for analysis in analyses:
            sources = self._extract_sources(analysis)
            sinks = self._find_sinks_in_analysis(analysis, repo_path)
            for source in sources:
                for sink in sinks:
                    confidence = self._estimate_flow_confidence(source, sink, analysis)
                    if confidence > 0.1:
                        flows.append(TaintFlow(
                            source=source,
                            sink=sink,
                            path=[f"{source.file}:{source.line} -> {sink.file}:{sink.line}"],
                            confidence=confidence,
                        ))

        logger.info(f"Data flow: {len(flows)} taint paths found")
        return sorted(flows, key=lambda f: f.confidence, reverse=True)

    def _extract_sources(self, analysis: FileAnalysis) -> list[TaintSource]:
        sources: list[TaintSource] = []

        if analysis.language == "python":
            sources.extend(self._python_sources(analysis))
        elif analysis.language in ("javascript", "typescript"):
            sources.extend(self._javascript_sources(analysis))

        return sources

    def _python_sources(self, analysis: FileAnalysis) -> list[TaintSource]:
        sources: list[TaintSource] = []
        import re

        path = Path(analysis.path)

        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return sources

        source_lines = source.split("\n")

        request_patterns = [
            (r"request\.(args|form|json|data|files|headers|cookies)", "HTTP_REQUEST"),
            (r"request\.(args|form|json|data)\.get\(", "HTTP_GET_PARAM"),
            (r"input\s*\(", "STDIN"),
            (r"sys\.argv", "CLI_ARG"),
            (r"os\.environ\.get\(", "ENV_VAR"),
            (r"open\s*\([^)]*['\"]r", "FILE_READ"),
            (r"\.recv\s*\(", "SOCKET"),
            (r"yaml\.load\s*\(", "YAML_DESERIALIZE"),
            (r"pickle\.loads?\s*\(", "PICKLE_DESERIALIZE"),
            (r"json\.loads\s*\(.*request\b", "JSON_INPUT"),
        ]

        for pattern, source_type in request_patterns:
            for match in re.finditer(pattern, source):
                line_num = source[:match.start()].count("\n") + 1
                line_text = source_lines[line_num - 1].strip()
                sources.append(TaintSource(
                    file=analysis.path, line=line_num,
                    variable=match.group(0).split("(")[0].strip(),
                    source_type=source_type,
                    description=line_text[:120],
                ))

        return sources

    def _javascript_sources(self, analysis: FileAnalysis) -> list[TaintSource]:
        sources: list[TaintSource] = []
        import re

        path = Path(analysis.path)

        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return sources

        source_lines = source.split("\n")

        request_patterns = [
            (r"req\.(body|query|params|headers|cookies)\b", "HTTP_REQUEST"),
            (r"req\.(body|query|params)\.(\w+)", "HTTP_PARAM"),
            (r"process\.argv", "CLI_ARG"),
            (r"process\.env\.(\w+)", "ENV_VAR"),
            (r"readFileSync\s*\(", "FILE_READ"),
            (r"JSON\.parse\s*\(.*req\b", "JSON_INPUT"),
        ]

        for pattern, source_type in request_patterns:
            for match in re.finditer(pattern, source):
                line_num = source[:match.start()].count("\n") + 1
                line_text = source_lines[line_num - 1].strip()
                sources.append(TaintSource(
                    file=analysis.path, line=line_num,
                    variable=match.group(0),
                    source_type=source_type,
                    description=line_text[:120],
                ))

        return sources

    def _find_sinks_in_analysis(self, analysis: FileAnalysis, repo_path: Path) -> list[SinkMatch]:
        filepath = repo_path / analysis.path
        if not filepath.exists():
            filepath = Path(analysis.path)

        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except Exception:
            return []

        return self.sink_finder.find_in_file(filepath, analysis.language, source)

    def _estimate_flow_confidence(
        self, source: TaintSource, sink: SinkMatch, analysis: FileAnalysis
    ) -> float:
        score = 0.0

        if source.file == sink.file:
            score += 0.6

        if source.line < sink.line:
            score += 0.1

        compatible_pairs = {
            ("HTTP_REQUEST", "sql_injection"): 0.3,
            ("HTTP_REQUEST", "ssrf"): 0.3,
            ("HTTP_REQUEST", "command_execution"): 0.3,
            ("HTTP_REQUEST", "deserialization"): 0.2,
            ("HTTP_REQUEST", "path_traversal"): 0.2,
            ("HTTP_REQUEST", "template_injection"): 0.2,
            ("CLI_ARG", "command_execution"): 0.3,
            ("FILE_READ", "deserialization"): 0.2,
            ("YAML_DESERIALIZE", "command_execution"): 0.2,
            ("PICKLE_DESERIALIZE", "command_execution"): 0.3,
        }

        compat_score = compatible_pairs.get((source.source_type, sink.category), 0.0)
        score += compat_score

        severity_weights = {"CRITICAL": 0.3, "HIGH": 0.2, "MEDIUM": 0.1}
        score += severity_weights.get(sink.severity, 0)

        return min(score, 1.0)
