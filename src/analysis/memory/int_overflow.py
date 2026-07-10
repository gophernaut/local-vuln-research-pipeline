"""Integer overflow analyzer — detects integer overflow in security-sensitive operations.

Checks: allocation sizes, buffer offsets, array indices, size calculations,
loop bounds, comparison operands used in memory operations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()

ARITH_PATTERNS = [
    (r"(\w+)\s*\*\s*(\w+)", "multiply"),
    (r"(\w+)\s*\+\s*(\w+)", "add"),
    (r"(\w+)\s*<<\s*(\w+)", "left_shift"),
    (r"(\w+)\s*-\s*(\w+)", "subtract"),
]

SIZE_CONTEXTS = [
    (r"\bmalloc\s*\(", "allocation"),
    (r"\bcalloc\s*\(", "allocation"),
    (r"\brealloc\s*\(", "reallocation"),
    (r"\balloca\s*\(", "stack_allocation"),
    (r"\bmemcpy\s*\(", "buffer_copy"),
    (r"\bmemmove\s*\(", "buffer_copy"),
    (r"\bstrcpy\s*\(", "string_copy"),
    (r"\bstrncpy\s*\(", "string_copy"),
    (r"\bstrcat\s*\(", "string_concat"),
    (r"\bnew\s+\w+\s*\[", "new_array"),
    (r"\bVec::with_capacity\s*\(", "vec_allocation"),
    (r"\bBox::new\s*\(", "box_allocation"),
]

CHECK_PATTERNS = [
    (r"if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)", "upper_bound"),
    (r"if\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)", "lower_bound"),
    (r"if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)", "upper_bound_inclusive"),
    (r"if\s*\(\s*(\w+)\s*<=\s*(\w+)\s*\)", "lower_bound_inclusive"),
    (r"if\s*\(\s*(\w+)\s*==\s*0\s*\)", "null_check"),
    (r"if\s*\(\s*(\w+)\s*!=\s*0\s*\)", "null_check"),
    (r"assert\s*\(\s*(\w+)\s*[<>]=?\s*(\w+)", "assertion"),
    (r"\bCHECK_OVERFLOW\b", "overflow_check"),
    (r"\bCHECK_SIZE\b", "size_check"),
    (r"\bOVERFLOW_OK\b", "overflow_ok"),
    (r"\b__builtin_mul_overflow\b", "builtin_check"),
    (r"\b__builtin_add_overflow\b", "builtin_check"),
    (r"\bsafe_mul\b", "safe_mul"),
    (r"\bsafe_add\b", "safe_add"),
    (r"\bchecked_mul\b", "checked_mul"),
    (r"\bchecked_add\b", "checked_add"),
    (r"\bwrapping_mul\b", "wrapping_mul"),
    (r"\bwrapping_add\b", "wrapping_add"),
]

DANGER_SIZES = {
    "input", "buf", "data", "body", "request", "param", "arg", "argv",
    "content", "content_length", "len", "size", "n", "sz", "count",
    "user_input", "query", "header", "path", "filename", "url",
    "stdin", "env", "recv", "read", "fread", "getline", "line",
    "str", "msg", "packet", "payload", "frame", "chunk",
}


@dataclass
class IntOverflowFinding:
    file: str
    line: int
    vulnerability_class: str
    description: str
    severity: str
    confidence: float
    cwe_id: str
    operation: str = ""
    expression: str = ""


class IntOverflowAnalyzer:
    def analyze_file(self, filepath: Path, source: str, language: str) -> list[IntOverflowFinding]:
        if language not in ("c", "cpp", "rust"):
            return []

        findings = []
        lines = source.split("\n")

        for size_context_pattern, context_type in SIZE_CONTEXTS:
            for m in re.finditer(size_context_pattern, source):
                context_line = source[:m.start()].count("\n") + 1
                context_start = max(0, context_line - 5)
                context_end = min(len(lines), context_line + 10)
                context_block = "\n".join(lines[context_start:context_end])

                for arith_pattern, op_name in ARITH_PATTERNS:
                    for am in re.finditer(arith_pattern, context_block):
                        operands = [am.group(1), am.group(2)]
                        has_check = self._has_overflow_check(context_block, operands)

                        is_danger = any(
                            any(d in operand.lower() for d in DANGER_SIZES)
                            for operand in operands
                        )

                        if is_danger and not has_check:
                            arith_line = context_start + context_block[:am.start()].count("\n") + 1
                            findings.append(IntOverflowFinding(
                                file=str(filepath), line=arith_line,
                                vulnerability_class="Integer Overflow → Memory Corruption",
                                description=f"{context_type} size uses {op_name} operation "
                                           f"'{' '.join(operands)}' without overflow check. "
                                           f"If result overflows, a small buffer is allocated "
                                           f"and subsequent writes overflow it.",
                                severity="HIGH", confidence=0.7,
                                cwe_id="CWE-190",
                                operation=op_name,
                                expression=f"{operands[0]} {op_name} {operands[1]}",
                            ))

        return findings

    def _has_overflow_check(self, context: str, operands: list[str]) -> bool:
        for pattern, check_type in CHECK_PATTERNS:
            if re.search(pattern, context):
                return True
        return False
