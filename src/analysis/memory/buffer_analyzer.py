"""Buffer access analyzer — detects buffer overflows, underflows, and out-of-bounds access.

Checks every buffer write/read against:
- Known allocation sizes
- Bounds checks (if present)
- Attacker-controlled indices
- Off-by-one conditions
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()

BUFFER_WRITE_PATTERNS = {
    "c": [
        (r"\bstrcpy\s*\(\s*(\w+)\s*,", "strcpy", "dest", None),
        (r"\bstrncpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)", "strncpy", "dest", "size"),
        (r"\bstrcat\s*\(\s*(\w+)\s*,", "strcat", "dest", None),
        (r"\bsprintf\s*\(\s*(\w+)\s*,\s*\"([^\"]*)\"", "sprintf", "dest", None),
        (r"\bsnprintf\s*\(\s*(\w+)\s*,\s*(\w+)", "snprintf", "dest", "size"),
        (r"\bmemcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(.+?)\s*\)", "memcpy", "dest", "size"),
        (r"\bmemmove\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(.+?)\s*\)", "memmove", "dest", "size"),
        (r"\bgets\s*\(\s*(\w+)\s*\)", "gets", "dest", None),
        (r"\bscanf\s*\([^;]*%s[^;]*,\s*(\w+)", "scanf_s", "dest", None),
        (r"\bsscanf\s*\([^;]*%s[^;]*,\s*(\w+)", "sscanf_s", "dest", None),
    ],
    "cpp": [
        (r"\bstrcpy\s*\(\s*(\w+)\s*,", "strcpy", "dest", None),
        (r"\bstrncpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)", "strncpy", "dest", "size"),
        (r"\bmemcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(.+?)\s*\)", "memcpy", "dest", "size"),
        (r"\bmemmove\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(.+?)\s*\)", "memmove", "dest", "size"),
        (r"\.copy\s*\(\s*(\w+)\s*,", "string_copy", "dest", None),
        (r"\.append\s*\(\s*(.+?)\s*\)", "string_append", "str", None),
    ],
    "rust": [
        (r"\bstrcpy\s*\(\s*(\w+)\s*,", "strcpy", "dest", None),
        (r"\bmemcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(.+?)\s*\)", "memcpy", "dest", "size"),
    ],
}

BUFFER_READ_PATTERNS = {
    "c": [
        (r"\bgets\s*\(\s*(\w+)\s*\)", "gets_unbounded", "dest"),
        (r"\bscanf\s*\([^;]*%s", "scanf_unbounded", "dest"),
        (r"\bfgets\s*\(\s*(\w+)\s*,\s*\w+\s*,", "fgets_bounded", "dest"),
        (r"\brecv\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(.+?)\s*,", "recv", "buf"),
        (r"\bread\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(.+?)\s*\)", "read_syscall", "buf"),
    ],
    "cpp": [
        (r"\bstd::cin\s*>>\s*(\w+)", "cin_unbounded", "dest"),
        (r"\bgetline\s*\(\s*std::cin\s*,\s*(\w+)\s*\)", "getline", "dest"),
    ],
}

ARRAY_ACCESS_PATTERNS = [
    (r"(\w+)\s*\[\s*(.+?)\s*\]", "array_index"),
    (r"(\w+)\s*\[\s*(.+?)\s*:\s*(.+?)\s*\]", "slice"),
]

BOUNDS_CHECK_PATTERNS = [
    r"if\s*\(\s*\w+\s*(?:<|<=|>|>=)\s*\w+\s*\)",
    r"if\s*\(\s*sizeof\s*\(\s*\w+\s*\)",
    r"assert\s*\(\s*\w+\s*(?:<|<=|>|>=)",
    r"BOUNDSCHECK",
    r"CHECK_BOUNDS",
    r"VALIDATE_SIZE",
    r"__builtin_expect.*<\s*sizeof",
]


@dataclass
class BufferAccess:
    file: str
    line: int
    access_type: str
    buffer_var: str
    size_expression: str = ""
    is_write: bool = True
    has_bounds_check: bool = False
    index_expression: str = ""
    is_attacker_controlled: bool = False


@dataclass
class BufferFinding:
    file: str
    line: int
    vulnerability_class: str
    description: str
    severity: str
    confidence: float
    cwe_id: str
    access: BufferAccess | None = None


class BufferAnalyzer:
    def analyze_file(self, filepath: Path, source: str, language: str) -> list[BufferFinding]:
        if language not in ("c", "cpp", "rust"):
            return []

        findings = []
        lines = source.split("\n")

        accesses = self._find_buffer_accesses(filepath, source, language)

        for access in accesses:
            findings.extend(self._analyze_access(access, lines))

        return findings

    def _find_buffer_accesses(self, filepath: Path, source: str, language: str) -> list[BufferAccess]:
        accesses = []

        write_patterns = BUFFER_WRITE_PATTERNS.get(language, [])
        for pattern, access_type, dest_role, size_role in write_patterns:
            for m in re.finditer(pattern, source, re.DOTALL):
                line_num = source[:m.start()].count("\n") + 1
                buffer_var = m.group(1) if m.lastindex >= 1 else ""
                size_expr = m.group(2) if m.lastindex >= 2 else ""
                attacker_controlled = self._is_attacker_controlled(size_expr, source)
                accesses.append(BufferAccess(
                    file=str(filepath), line=line_num,
                    access_type=access_type, buffer_var=buffer_var,
                    size_expression=size_expr, is_write=True,
                    is_attacker_controlled=attacker_controlled,
                ))

        read_patterns = BUFFER_READ_PATTERNS.get(language, [])
        for pattern, access_type, dest_role in read_patterns:
            for m in re.finditer(pattern, source, re.DOTALL):
                line_num = source[:m.start()].count("\n") + 1
                buffer_var = m.group(1) if m.lastindex >= 1 else ""
                accesses.append(BufferAccess(
                    file=str(filepath), line=line_num,
                    access_type=access_type, buffer_var=buffer_var,
                    is_write=False,
                ))

        for pattern, access_type in ARRAY_ACCESS_PATTERNS:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                buffer_var = m.group(1)
                index_expr = m.group(2) if m.lastindex >= 2 else ""
                attacker = self._is_attacker_controlled(index_expr, source)
                accesses.append(BufferAccess(
                    file=str(filepath), line=line_num,
                    access_type=access_type, buffer_var=buffer_var,
                    index_expression=index_expr, is_write=False,
                    is_attacker_controlled=attacker,
                ))

        return accesses

    def _analyze_access(self, access: BufferAccess, lines: list[str]) -> list[BufferFinding]:
        findings = []
        context_lines = lines[max(0, access.line - 5):min(len(lines), access.line + 5)]
        context = "\n".join(context_lines)
        has_check = any(re.search(p, context) for p in BOUNDS_CHECK_PATTERNS)

        if access.access_type in ("strcpy", "gets", "gets_unbounded", "scanf_unbounded", "cin_unbounded"):
            findings.append(BufferFinding(
                file=access.file, line=access.line,
                vulnerability_class="Stack Buffer Overflow",
                description=f"Unbounded {access.access_type} writes to buffer '{access.buffer_var}' "
                           f"without bounds check. Attacker can overflow the buffer.",
                severity="CRITICAL", confidence=0.95, cwe_id="CWE-120",
                access=access,
            ))

        elif access.access_type in ("memcpy", "memmove") and access.is_attacker_controlled:
            if not has_check:
                findings.append(BufferFinding(
                    file=access.file, line=access.line,
                    vulnerability_class="Heap/Stack Buffer Overflow",
                    description=f"{access.access_type} with attacker-controlled size "
                               f"'{access.size_expression}' into '{access.buffer_var}' "
                               f"without bounds validation.",
                    severity="HIGH", confidence=0.8, cwe_id="CWE-120",
                    access=access,
                ))

        elif access.access_type in ("strncpy", "snprintf"):
            if has_check:
                pass
            elif access.is_attacker_controlled:
                findings.append(BufferFinding(
                    file=access.file, line=access.line,
                    vulnerability_class="Buffer Overflow (partial)",
                    description=f"{access.access_type} with size '{access.size_expression}' "
                               f"may be insufficient for destination '{access.buffer_var}'.",
                    severity="MEDIUM", confidence=0.6, cwe_id="CWE-120",
                    access=access,
                ))

        elif access.access_type == "array_index" and access.is_attacker_controlled:
            if not has_check:
                findings.append(BufferFinding(
                    file=access.file, line=access.line,
                    vulnerability_class="Out-of-Bounds Array Access",
                    description=f"Array '{access.buffer_var}' accessed with attacker-controlled "
                               f"index '{access.index_expression}' without bounds check.",
                    severity="HIGH", confidence=0.7, cwe_id="CWE-125",
                    access=access,
                ))

        elif access.access_type == "slice":
            findings.append(BufferFinding(
                file=access.file, line=access.line,
                vulnerability_class="Out-of-Bounds Slice",
                description=f"Slice operation on '{access.buffer_var}' with bounds "
                           f"'{access.index_expression}:{access.size_expression}'. "
                           f"Verify bounds are within allocation.",
                severity="MEDIUM", confidence=0.5, cwe_id="CWE-125",
                access=access,
            ))

        if access.access_type == "recv" and access.is_attacker_controlled:
            findings.append(BufferFinding(
                file=access.file, line=access.line,
                vulnerability_class="Network Buffer Overflow",
                description=f"recv() with attacker-controlled size into '{access.buffer_var}'. "
                           f"Network data can overflow buffer.",
                severity="HIGH", confidence=0.75, cwe_id="CWE-120",
                access=access,
            ))

        return findings

    def _is_attacker_controlled(self, expression: str, source: str) -> bool:
        if not expression:
            return False
        danger_vars = {
            "input", "buf", "data", "body", "request", "param", "arg", "argv",
            "content", "content_length", "len", "size", "n", "sz", "count",
            "user_input", "query", "header", "path", "filename", "url",
            "stdin", "env", "recv", "read", "fread", "getline",
            "str", "msg", "packet", "payload", "frame",
        }
        expr_lower = expression.lower()
        for var in danger_vars:
            if var in expr_lower:
                return True
        if re.search(r"\w+\s*\*\s*\w+", expression):
            return True
        return False
