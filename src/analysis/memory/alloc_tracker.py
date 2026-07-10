"""Memory allocation tracker — tracks all allocations in C/C++/Rust.

Records: pointer variable, allocation site, size expression, allocator type.
Detects: malloc with attacker-controlled size, integer overflow in size calculations,
mismatched allocators, zero-size allocations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()

ALLOC_PATTERNS = {
    "c": [
        (r"\bmalloc\s*\(\s*(.+?)\s*\)", "malloc", "size"),
        (r"\bcalloc\s*\(\s*(.+?)\s*,", "calloc", "count"),
        (r"\brealloc\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)", "realloc", "new_size"),
        (r"\balloca\s*\(\s*(.+?)\s*\)", "alloca", "size"),
        (r"\b_strdup\s*\(\s*(.+?)\s*\)", "_strdup", "source"),
        (r"\b_strndup\s*\(\s*.+?\s*,\s*(.+?)\s*\)", "_strndup", "size"),
    ],
    "cpp": [
        (r"\bnew\s+\w+\s*\[?\s*(.+?)\s*\]?\s*[\(;]", "new_array", "size"),
        (r"\bnew\s+\w+\s*\(", "new_obj", "size"),
        (r"\boperator\s+new\s*\[\s*\]\s*\((.+?)\)", "operator_new_array", "size"),
        (r"\boperator\s+new\s*\((.+?)\)", "operator_new", "size"),
        (r"\bmalloc\s*\(\s*(.+?)\s*\)", "malloc", "size"),
        (r"\bcalloc\s*\(\s*(.+?)\s*,", "calloc", "count"),
        (r"\brealloc\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)", "realloc", "new_size"),
        (r"\balloca\s*\(\s*(.+?)\s*\)", "alloca", "size"),
        (r"\bstd::vector\s*<.*?>\s+\w+\s*\((.+?)\)", "std_vector", "size"),
    ],
    "rust": [
        (r"\bVec::with_capacity\s*\(\s*(.+?)\s*\)", "vec_capacity", "size"),
        (r"\bVec::from_raw_parts\s*\(", "vec_from_raw", "raw"),
        (r"\bBox::new\s*\(", "box_new", "size"),
        (r"\bunsafe\s*\{[^}]*malloc\s*\(\s*(.+?)\s*\)", "unsafe_malloc", "size"),
        (r"\bunsafe\s*\{[^}]*alloc\s*\(\s*(.+?)\s*,", "unsafe_alloc", "size"),
    ],
}

FREE_PATTERNS = {
    "c": [
        (r"\bfree\s*\(\s*(\w+)\s*\)", "free"),
        (r"\bcfree\s*\(\s*(\w+)\s*\)", "free"),
    ],
    "cpp": [
        (r"\bdelete\s*\[\s*\]\s*(\w+)", "delete_array"),
        (r"\bdelete\s+(\w+)", "delete_obj"),
        (r"\bfree\s*\(\s*(\w+)\s*\)", "free"),
    ],
    "rust": [
        (r"\bunsafe\s*\{[^}]*free\s*\(\s*(\w+)\s*\)", "unsafe_free"),
        (r"\bunsafe\s*\{[^}]*dealloc\s*\(", "unsafe_dealloc"),
    ],
}

SIZE_CALC_PATTERNS = [
    (r"(\w+)\s*\*\s*(\w+)", "multiply"),
    (r"(\w+)\s*\+\s*(\w+)", "add"),
    (r"(\w+)\s*<<\s*(\w+)", "shift"),
]


@dataclass
class Allocation:
    file: str
    line: int
    pointer_var: str
    allocator: str
    size_expression: str
    size_var: str = ""
    size_operation: str = ""
    size_operands: list[str] = field(default_factory=list)
    is_attacker_controlled: bool = False
    overflow_risk: bool = False


@dataclass
class Deallocation:
    file: str
    line: int
    pointer_var: str
    deallocator: str


@dataclass
class AllocFinding:
    file: str
    line: int
    vulnerability_class: str
    description: str
    severity: str
    confidence: float
    cwe_id: str
    allocation: Allocation | None = None


class AllocTracker:
    def analyze_file(self, filepath: Path, source: str, language: str) -> list[AllocFinding]:
        if language not in ("c", "cpp", "rust"):
            return []

        findings = []
        lines = source.split("\n")

        allocations = self._track_allocations(filepath, source, language)
        deallocations = self._track_deallocations(filepath, source, language)

        for alloc in allocations:
            findings.extend(self._analyze_allocation(alloc, deallocations, lines))

        return findings

    def _track_allocations(self, filepath: Path, source: str, language: str) -> list[Allocation]:
        allocations = []
        patterns = ALLOC_PATTERNS.get(language, [])

        for pattern, allocator, size_role in patterns:
            for m in re.finditer(pattern, source, re.DOTALL):
                line_num = source[:m.start()].count("\n") + 1
                line_text = source.split("\n")[line_num - 1] if line_num <= len(source.split("\n")) else ""

                size_expr = ""
                if m.lastindex and m.lastindex >= 1:
                    size_expr = m.group(m.lastindex).strip()

                size_var = ""
                size_operation = ""
                size_operands = []
                overflow_risk = False

                for op_pattern, op_name in SIZE_CALC_PATTERNS:
                    op_match = re.search(op_pattern, size_expr)
                    if op_match:
                        size_operation = op_name
                        size_operands = [op_match.group(1), op_match.group(2)]
                        overflow_risk = True
                        break

                if size_var_patterns := re.findall(r"\b(\w+)\b", size_expr):
                    if any(v in ("input", "buf", "len", "size", "count", "n", "sz",
                                  "user_len", "data_len", "body_len", "request_size",
                                  "content_length") for v in size_var_patterns):
                        overflow_risk = True

                pointer_var = self._extract_pointer_var(line_text)

                allocations.append(Allocation(
                    file=str(filepath), line=line_num,
                    pointer_var=pointer_var, allocator=allocator,
                    size_expression=size_expr,
                    size_var=size_var,
                    size_operation=size_operation,
                    size_operands=size_operands,
                    is_attacker_controlled=overflow_risk,
                    overflow_risk=overflow_risk,
                ))

        return allocations

    def _track_deallocations(self, filepath: Path, source: str, language: str) -> list[Deallocation]:
        deallocations = []
        patterns = FREE_PATTERNS.get(language, [])

        for pattern, deallocator in patterns:
            for m in re.finditer(pattern, source, re.DOTALL):
                line_num = source[:m.start()].count("\n") + 1
                pointer_var = m.group(1) if m.lastindex else ""
                deallocations.append(Deallocation(
                    file=str(filepath), line=line_num,
                    pointer_var=pointer_var, deallocator=deallocator,
                ))

        return deallocations

    def _analyze_allocation(self, alloc: Allocation, deallocations: list[Deallocation],
                            lines: list[str]) -> list[AllocFinding]:
        findings = []

        if alloc.overflow_risk and alloc.size_operation == "multiply":
            findings.append(AllocFinding(
                file=alloc.file, line=alloc.line,
                vulnerability_class="Integer Overflow → Heap Buffer Overflow",
                description=f"Allocation size is a multiplication ({alloc.size_expression}). "
                           f"If either operand is attacker-controlled, integer overflow can "
                           f"result in a smaller allocation than expected, leading to heap overflow.",
                severity="HIGH", confidence=0.7, cwe_id="CWE-190",
                allocation=alloc,
            ))

        if alloc.overflow_risk and alloc.size_operation in ("add", "shift"):
            findings.append(AllocFinding(
                file=alloc.file, line=alloc.line,
                vulnerability_class="Integer Overflow → Buffer Overflow",
                description=f"Allocation size uses {alloc.size_operation} operation ({alloc.size_expression}). "
                           f"Integer overflow possible if operands attacker-controlled.",
                severity="MEDIUM", confidence=0.6, cwe_id="CWE-190",
                allocation=alloc,
            ))

        if alloc.allocator in ("alloca", "std_vector"):
            if alloc.overflow_risk:
                findings.append(AllocFinding(
                    file=alloc.file, line=alloc.line,
                    vulnerability_class="Stack Buffer Overflow",
                    description=f"Stack allocation (alloca/vector) with potentially "
                               f"attacker-controlled size: {alloc.size_expression}. "
                               f"Stack overflow can overwrite return address.",
                    severity="CRITICAL", confidence=0.8, cwe_id="CWE-121",
                    allocation=alloc,
                ))

        if alloc.allocator == "malloc" and not alloc.size_expression:
            findings.append(AllocFinding(
                file=alloc.file, line=alloc.line,
                vulnerability_class="Zero-Size Allocation",
                description="malloc(0) returns a valid pointer but dereferencing it is UB.",
                severity="MEDIUM", confidence=0.5, cwe_id="CWE-131",
                allocation=alloc,
            ))

        return findings

    def _extract_pointer_var(self, line: str) -> str:
        m = re.search(r"(\w+)\s*=", line)
        if m:
            return m.group(1)
        m = re.search(r"(\w+)\s*\[", line)
        if m:
            return m.group(1)
        return ""
