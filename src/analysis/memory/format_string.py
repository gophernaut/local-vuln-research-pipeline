"""Format string vulnerability analyzer — detects attacker-controlled format strings.

Checks: printf/scanf with non-literal format strings, logging functions
with user input, format string in dynamically constructed output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()

FORMAT_FUNCTIONS = {
    "c": [
        (r"\bprintf\s*\(\s*(\w+)", "printf"),
        (r"\bsprintf\s*\(\s*\w+\s*,\s*(\w+)", "sprintf"),
        (r"\bfprintf\s*\(\s*\w+\s*,\s*(\w+)", "fprintf"),
        (r"\bsnprintf\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)", "snprintf"),
        (r"\bdprintf\s*\(\s*\w+\s*,\s*(\w+)", "dprintf"),
        (r"\bsyslog\s*\(\s*\w+\s*,\s*(\w+)", "syslog"),
        (r"\bwarn\s*\(\s*(\w+)", "warn"),
        (r"\bxprintf\s*\(\s*(\w+)", "xprintf"),
    ],
    "cpp": [
        (r"\bprintf\s*\(\s*(\w+)", "printf"),
        (r"\bfprintf\s*\(\s*\w+\s*,\s*(\w+)", "fprintf"),
        (r"\bsprintf\s*\(\s*\w+\s*,\s*(\w+)", "sprintf"),
    ],
    "rust": [
        (r"\bunsafe\s*\{[^}]*libc::printf\s*\(\s*(\w+)", "unsafe_printf"),
        (r"\bunsafe\s*\{[^}]*CString::new\s*\([^)]*\)", "unsafe_cstring"),
        (r"\bstd::fmt::write\s*\(", "format_write"),
    ],
}

LITERAL_FORMAT = re.compile(r'^["\'].*["\']$|^\s*$', re.DOTALL)

USER_INPUT_VARS = {
    "input", "buf", "data", "body", "request", "param", "arg", "argv",
    "content", "line", "str", "msg", "packet", "payload", "frame",
    "user_input", "query", "header", "path", "filename", "url",
    "stdin", "env", "recv", "read", "fread", "getline", "err",
    "message", "text", "value", "result", "output", "response",
}


@dataclass
class FormatStringFinding:
    file: str
    line: int
    vulnerability_class: str
    description: str
    severity: str
    confidence: float
    cwe_id: str
    function_name: str = ""
    format_var: str = ""


class FormatStringAnalyzer:
    def analyze_file(self, filepath: Path, source: str, language: str) -> list[FormatStringFinding]:
        if language not in ("c", "cpp", "rust"):
            return []

        findings = []
        patterns = FORMAT_FUNCTIONS.get(language, [])

        for pattern, func_name in patterns:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                format_var = m.group(1) if m.lastindex else ""

                if not format_var:
                    continue

                if LITERAL_FORMAT.match(format_var):
                    continue

                is_user = any(u in format_var.lower() for u in USER_INPUT_VARS)
                confidence = 0.85 if is_user else 0.5

                if is_user:
                    findings.append(FormatStringFinding(
                        file=str(filepath), line=line_num,
                        vulnerability_class="Format String Vulnerability",
                        description=f"{func_name} called with non-literal format string "
                                   f"'{format_var}' which appears to be user-controlled. "
                                   f"Attacker can read/write arbitrary memory using format "
                                   f"specifiers like %x, %n, %s.",
                        severity="CRITICAL", confidence=confidence, cwe_id="CWE-134",
                        function_name=func_name, format_var=format_var,
                    ))
                else:
                    findings.append(FormatStringFinding(
                        file=str(filepath), line=line_num,
                        vulnerability_class="Format String (potential)",
                        description=f"{func_name} called with non-literal format string "
                                   f"'{format_var}'. Verify this is not attacker-controlled.",
                        severity="MEDIUM", confidence=confidence, cwe_id="CWE-134",
                        function_name=func_name, format_var=format_var,
                    ))

        return findings
