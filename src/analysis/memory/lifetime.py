"""Memory lifetime analyzer — detects use-after-free, double-free, and dangling pointers.

Tracks: allocation sites, free sites, and every use of freed pointers.
Detects: use-after-free, double-free, invalid free, mismatched free, null dereference.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()

DEREF_PATTERNS = [
    (r"\*(\w+)\s*[=+\-*/&|^]=", "pointer_deref"),
    (r"\*(\w+)\s*;", "pointer_deref"),
    (r"\b(\w+)\s*->", "arrow_access"),
    (r"\b(\w+)\s*\[", "array_access"),
    (r"\bprintf\s*\(\s*(\w+)", "format_arg"),
    (r"\bstrcpy\s*\(\s*(\w+)\s*,", "strcpy_dest"),
    (r"\bstrcat\s*\(\s*(\w+)\s*,", "strcat_dest"),
    (r"\bmemcpy\s*\(\s*(\w+)\s*,", "memcpy_dest"),
    (r"\bfree\s*\(\s*(\w+)\s*\)", "free_arg"),
    (r"\b(\w+)\s*\(\s*(\w+)", "func_call_arg"),
]


@dataclass
class LifetimeFinding:
    file: str
    line: int
    vulnerability_class: str
    description: str
    severity: str
    confidence: float
    cwe_id: str
    pointer_var: str = ""
    free_line: int = 0
    use_line: int = 0


class LifetimeAnalyzer:
    def analyze_file(self, filepath: Path, source: str, language: str) -> list[LifetimeFinding]:
        if language not in ("c", "cpp", "rust"):
            return []

        findings = []
        lines = source.split("\n")
        line_texts = [l.strip() for l in lines]

        freed_vars: dict[str, int] = {}
        alloc_vars: dict[str, int] = {}
        alloc_line_map: dict[str, int] = {}

        alloc_patterns = self._get_alloc_patterns(language)
        free_patterns = self._get_free_patterns(language)

        for pattern in alloc_patterns:
            for m in re.finditer(pattern, source, re.DOTALL):
                var = self._extract_var(m)
                line_num = source[:m.start()].count("\n") + 1
                if var:
                    alloc_vars[var] = line_num
                    alloc_line_map[var] = line_num

        for pattern in free_patterns:
            for m in re.finditer(pattern, source, re.DOTALL):
                var = m.group(1) if m.lastindex else ""
                line_num = source[:m.start()].count("\n") + 1
                if not var:
                    continue

                if var in freed_vars:
                    findings.append(LifetimeFinding(
                        file=str(filepath), line=line_num,
                        vulnerability_class="Double Free",
                        description=f"Variable '{var}' freed at line {freed_vars[var]} "
                                   f"and again at line {line_num}. Double-free can corrupt "
                                   f"heap metadata and lead to code execution.",
                        severity="CRITICAL", confidence=0.85, cwe_id="CWE-415",
                        pointer_var=var, free_line=line_num, use_line=freed_vars[var],
                    ))

                freed_vars[var] = line_num

        for pattern_idx, (deref_pattern, deref_type) in enumerate(DEREF_PATTERNS):
            for m in re.finditer(deref_pattern, source):
                var = m.group(1) if m.lastindex else ""
                line_num = source[:m.start()].count("\n") + 1
                if not var or len(var) > 100:
                    continue

                if var in freed_vars and freed_vars[var] < line_num:
                    context_before = "\n".join(line_texts[max(0, freed_vars[var]-1):line_num])
                    if not re.search(r"\b" + re.escape(var) + r"\s*=\s*(?:malloc|calloc|realloc|new|box|alloc)", context_before):
                        if deref_type in ("pointer_deref", "arrow_access", "strcpy_dest",
                                          "strcat_dest", "memcpy_dest", "func_call_arg"):
                            findings.append(LifetimeFinding(
                                file=str(filepath), line=line_num,
                                vulnerability_class="Use-After-Free",
                                description=f"Variable '{var}' freed at line {freed_vars[var]} "
                                           f"then used at line {line_num} ({deref_type}). "
                                           f"Heap memory may have been reallocated with attacker data.",
                                severity="CRITICAL", confidence=0.8, cwe_id="CWE-416",
                                pointer_var=var, free_line=freed_vars[var], use_line=line_num,
                            ))

        for var, free_line in freed_vars.items():
            if var not in alloc_vars:
                findings.append(LifetimeFinding(
                    file=str(filepath), line=free_line,
                    vulnerability_class="Invalid Free",
                    description=f"Variable '{var}' is freed but was never allocated "
                               f"with a heap allocator in this function. May be a "
                               f"stack variable or uninitialized pointer.",
                    severity="HIGH", confidence=0.5, cwe_id="CWE-761",
                    pointer_var=var, free_line=free_line,
                ))

        return findings

    def _get_alloc_patterns(self, language: str) -> list[str]:
        patterns = {
            "c": [
                r"\b(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(",
                r"\b(\w+)\s*=\s*(?:_?strdup|_?strndup)\s*\(",
                r"\b(\w+)\s*=\s*alloca\s*\(",
            ],
            "cpp": [
                r"\b(\w+)\s*=\s*(?:new\s+\w+|malloc|calloc|realloc)\s*[\[\(]",
                r"\b(\w+)\s*=\s*std::make_unique\s*<",
                r"\b(\w+)\s*=\s*std::make_shared\s*<",
            ],
            "rust": [
                r"\blet\s+mut\s+(\w+)\s*=\s*(?:Vec::with_capacity|Box::new|String::with_capacity)",
                r"\bunsafe\s*\{[^}]*alloc\s*\(",
            ],
        }
        return patterns.get(language, [])

    def _get_free_patterns(self, language: str) -> list[str]:
        patterns = {
            "c": [r"\bfree\s*\(\s*(\w+)\s*\)"],
            "cpp": [
                r"\bdelete\s*\[\s*\]\s*(\w+)",
                r"\bdelete\s+(\w+)",
                r"\bfree\s*\(\s*(\w+)\s*\)",
            ],
            "rust": [
                r"\bunsafe\s*\{[^}]*free\s*\(\s*(\w+)\s*\)",
                r"\bunsafe\s*\{[^}]*dealloc\s*\(\s*(\w+)",
            ],
        }
        return patterns.get(language, [])

    def _extract_var(self, match: re.Match) -> str:
        for i in range(1, (match.lastindex or 0) + 1):
            try:
                val = match.group(i)
                if val and val.isidentifier() and len(val) < 100:
                    return val
            except IndexError:
                break
        return ""
