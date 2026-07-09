"""Data flow / taint analysis — traces user-controlled data through code paths.

Detects entry points (sources) for ALL target types:
Web, CLI, native, PowerShell, kernel, syscalls, IPC, plugins, etc.
Detects sinks via sink_finder patterns.
Computes source→sink taint flow confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.ast_parser import FileAnalysis
from src.analysis.sink_finder import SinkFinder, SinkMatch
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


LANG_EXT_MAP = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".java": "java", ".kt": "java", ".scala": "java",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp", ".csx": "csharp",
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".rs": "rust",
    ".php": "php", ".phtml": "php",
}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
              "target", "build", "dist", "vendor", ".next", ".nuxt",
              ".idea", ".vscode", "bin", "obj", "Debug", "Release",
              "packages", "TestResults"}


class DataFlowAnalyzer:
    def __init__(self):
        self.sink_finder = SinkFinder()

    def analyze(self, repo_path: Path) -> list[TaintFlow]:
        flows: list[TaintFlow] = []

        for ext, lang in LANG_EXT_MAP.items():
            for filepath in repo_path.rglob(f"*{ext}"):
                if any(d in filepath.parts for d in SKIP_DIRS):
                    continue
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as f:
                        source = f.read()
                except Exception:
                    continue

                analysis = FileAnalysis(
                    path=str(filepath.relative_to(repo_path)),
                    language=lang,
                    lines=source.count("\n"),
                )

                sources = self._extract_sources(analysis, source)
                sinks = self.sink_finder.find_in_file(filepath, lang, source)

                for src in sources:
                    for sink in sinks:
                        confidence = self._flow_confidence(src, sink, analysis)
                        if confidence > 0.1:
                            flows.append(TaintFlow(
                                source=src, sink=sink,
                                path=[f"{src.file}:{src.line} -> {sink.file}:{sink.line}"],
                                confidence=confidence,
                            ))

        logger.info(f"Data flow: {len(flows)} taint paths found")
        return sorted(flows, key=lambda f: f.confidence, reverse=True)

    def _extract_sources(self, analysis: FileAnalysis, source: str) -> list[TaintSource]:
        lang = analysis.language
        if lang == "python":
            return self._python_sources(analysis, source)
        elif lang in ("javascript", "typescript"):
            return self._js_sources(analysis, source)
        elif lang == "csharp":
            return self._csharp_sources(analysis, source)
        elif lang in ("c", "cpp"):
            return self._native_sources(analysis, source)
        elif lang == "powershell":
            return self._powershell_sources(analysis, source)
        elif lang == "rust":
            return self._rust_sources(analysis, source)
        elif lang == "go":
            return self._go_sources(analysis, source)
        elif lang == "php":
            return self._php_sources(analysis, source)
        elif lang == "ruby":
            return self._ruby_sources(analysis, source)
        elif lang == "java":
            return self._java_sources(analysis, source)
        return []

    def _make_source(self, analysis, line_num, text, source_type):
        line_text = text.split("\n")[0] if text else ""
        return TaintSource(
            file=analysis.path, line=line_num,
            variable=source_type,
            source_type=source_type,
            description=line_text[:120],
        )

    def _python_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"@app\.(route|get|post|put|delete|patch)\(", "HTTP_ROUTE"),
            (r"request\.(args|form|json|data|files|headers|cookies)", "HTTP_REQUEST"),
            (r"request\.(args|form|json|data)\.get\(", "HTTP_PARAM"),
            (r"\binput\s*\(", "STDIN"),
            (r"\bsys\.argv", "CLI_ARG"),
            (r"\bos\.environ\.(?:get|__getitem__)\s*\(", "ENV_VAR"),
            (r"\bopen\s*\([^)]*['\"]r", "FILE_READ"),
            (r"\.recv\s*\(", "SOCKET_READ"),
            (r"\byaml\.load\s*\(", "YAML_DESERIALIZE"),
            (r"\bpickle\.(?:load|loads)\s*\(", "PICKLE_DESERIALIZE"),
            (r"\bjson\.loads?\s*\(.*request\b", "JSON_INPUT"),
            (r"\bargparse\.ArgumentParser", "CLI_ARG_PARSE"),
            (r"\bclick\.(?:command|option|argument)\(", "CLI_ARG"),
            (r"\btyper\.", "CLI_ARG"),
            (r"def\s+\w+\s*\(\s*(?:self|cls)?\s*,\s*(?:request|req)\b", "HTTP_HANDLER"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+120], stype))
        return results

    def _js_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"req\.(?:body|query|params|headers|cookies)\b", "HTTP_REQUEST"),
            (r"app\.(?:get|post|put|delete|patch|use)\s*\(", "HTTP_ROUTE"),
            (r"router\.(?:get|post|put|delete|patch|use)\s*\(", "HTTP_ROUTE"),
            (r"\bprocess\.argv", "CLI_ARG"),
            (r"\bprocess\.env\.\w+", "ENV_VAR"),
            (r"\breadFileSync\s*\(", "FILE_READ"),
            (r"\bfetch\s*\(", "HTTP_CLIENT"),
            (r"\baxios\.(?:get|post|put|delete)\s*\(", "HTTP_CLIENT"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _csharp_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\[Http(?:Get|Post|Put|Delete|Patch)\s*\(", "HTTP_ROUTE"),
            (r"\[FromBody\]", "HTTP_BODY"),
            (r"\[FromQuery\]", "HTTP_QUERY"),
            (r"\[FromRoute\]", "HTTP_ROUTE_PARAM"),
            (r"\[FromForm\]", "HTTP_FORM"),
            (r"HttpContext\.Request", "HTTP_REQUEST"),
            (r"\bConsole\.ReadLine\s*\(", "STDIN"),
            (r"\bEnvironment\.GetEnvironmentVariable\s*\(", "ENV_VAR"),
            (r"\bEnvironment\.GetCommandLineArgs\s*\(", "CLI_ARG"),
            (r"\bFile\.(?:ReadAllText|OpenRead|ReadAllLines|ReadAllBytes)\s*\(", "FILE_READ"),
            (r"\bWebClient\b", "HTTP_CLIENT"),
            (r"\bHttpClient\b", "HTTP_CLIENT"),
            (r"public\s+\w+\s+\w+\s*\([^)]*HttpRequest", "HTTP_HANDLER"),
            (r"\bDeserialize\w*\s*\(", "DESERIALIZE"),
            (r"\bBinaryFormatter\b", "DESERIALIZE"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _native_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\bmain\s*\(\s*(?:int|void)\s+\w+\s*,\s*(?:char|wchar_t)\s*\*\s*\w+\[\]", "CLI_ARG"),
            (r"\bgetenv\s*\(", "ENV_VAR"),
            (r"\bargv\[\w+\]", "CLI_ARG"),
            (r"\bfgets\s*\(", "STDIN"),
            (r"\bscanf\s*\(", "STDIN"),
            (r"\bgets\s*\(", "STDIN"),
            (r"\bread\s*\(", "FD_READ"),
            (r"\brecv\s*\(", "SOCKET_READ"),
            (r"\brecvfrom\s*\(", "SOCKET_READ"),
            (r"\bfopen\s*\(", "FILE_READ"),
            (r"\bopen\s*\(", "FILE_READ"),
            (r"\bmmap\s*\(", "FILE_MMAP"),
            (r"\bcopy_from_user\s*\(", "KERNEL_USERSPACE"),
            (r"\bcopyin\s*\(", "KERNEL_USERSPACE"),
            (r"\b__user\b", "KERNEL_USERSPACE"),
            (r"\bioctl\s*\(", "IOCTL"),
            (r"\.unlocked_ioctl\s*=", "IOCTL_HANDLER"),
            (r"\bSYSCALL_DEFINE\d*\(", "SYSCALL"),
            (r"\b__declspec\s*\(\s*dllexport\s*\)", "EXPORTED_API"),
            (r"\b__attribute__\s*\(\s*\(\s*visibility\s*\(\s*\"default\"\s*\)\s*\)\s*\)", "EXPORTED_API"),
            (r"\bXML_Parse\s*\(", "XML_PARSE"),
            (r"\bjson_parse\s*\(", "JSON_PARSE"),
            (r"\bprotobuf.*parse", "PROTOBUF_PARSE"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _powershell_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\bparam\s*\(", "PS_PARAM"),
            (r"\b\$args\b", "PS_ARGS"),
            (r"\b\$PSBoundParameters\b", "PS_PARAMS"),
            (r"\bRead-Host\b", "PS_STDIN"),
            (r"\bImport-Csv\b", "PS_FILE_READ"),
            (r"\bImport-Clixml\b", "PS_CLIXML_READ"),
            (r"\bGet-Content\b", "PS_FILE_READ"),
            (r"\bReceive-Job\b", "PS_JOB_INPUT"),
            (r"\bConvertFrom-Json\b", "PS_JSON_INPUT"),
            (r"\bConvertFrom-StringData\b", "PS_STRING_INPUT"),
            (r"\bInvoke-RestMethod\b", "PS_HTTP_CLIENT"),
            (r"\bInvoke-WebRequest\b", "PS_HTTP_CLIENT"),
            (r"\b\$env:\w+", "PS_ENV_VAR"),
            (r"\b\[Environment\]::GetEnvironmentVariable\b", "ENV_VAR"),
            (r"\b\$PSCmdlet\b", "PS_CMDLET"),
            (r"\b\$MyInvocation\b", "PS_INVOCATION"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _rust_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\bstd::env::args\s*\(", "CLI_ARG"),
            (r"\bstd::env::var\s*\(", "ENV_VAR"),
            (r"\bstd::io::stdin\s*\(", "STDIN"),
            (r"\bstd::fs::read\s*\(", "FILE_READ"),
            (r"\bstd::fs::read_to_string\s*\(", "FILE_READ"),
            (r"\bTcpStream::connect\s*\(", "SOCKET_READ"),
            (r"\bUdpSocket::bind\s*\(", "SOCKET_READ"),
            (r"\bunsafe\b", "UNSAFE_BLOCK"),
            (r"#\[no_mangle\]", "EXPORTED_API"),
            (r"\bpub\s+extern\s+\"C\"\b", "FFI_API"),
            (r"\bserde_json::from_str\s*\(", "JSON_DESERIALIZE"),
            (r"\bserde_json::from_reader\s*\(", "JSON_DESERIALIZE"),
            (r"\bbincode::deserialize\s*\(", "DESERIALIZE"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _go_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\bos\.Args\b", "CLI_ARG"),
            (r"\bos\.Getenv\s*\(", "ENV_VAR"),
            (r"\bos\.Stdin\b", "STDIN"),
            (r"\bos\.Open\s*\(", "FILE_READ"),
            (r"\bioutil\.ReadFile\s*\(", "FILE_READ"),
            (r"\bnet\.Listen\s*\(", "SOCKET_LISTEN"),
            (r"\bnet\.Dial\s*\(", "SOCKET_CONNECT"),
            (r"\bhttp\.HandleFunc\s*\(", "HTTP_ROUTE"),
            (r"\bjson\.NewDecoder\*\(", "JSON_DESERIALIZE"),
            (r"\bjson\.Unmarshal\s*\(", "JSON_DESERIALIZE"),
            (r"\bgob\.NewDecoder\s*\(", "DESERIALIZE"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _php_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\$\_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", "HTTP_REQUEST"),
            (r"\$_GET\[", "HTTP_GET"),
            (r"\$_POST\[", "HTTP_POST"),
            (r"\$_REQUEST\[", "HTTP_REQUEST"),
            (r"\$\_SERVER\[", "HTTP_SERVER"),
            (r"\bphp://input\b", "HTTP_BODY"),
            (r"\bphp://stdin\b", "STDIN"),
            (r"\bfopen\s*\(\s*\$", "FILE_READ"),
            (r"\bfile_get_contents\s*\(\s*\$", "FILE_READ"),
            (r"\$\_ENV\[", "ENV_VAR"),
            (r"\bgetenv\s*\(", "ENV_VAR"),
            (r"\$\_FILES\[", "FILE_UPLOAD"),
            (r"\bjson_decode\s*\(", "JSON_DESERIALIZE"),
            (r"\bunserialize\s*\(", "PHP_DESERIALIZE"),
            (r"\bcurl_exec\s*\(", "HTTP_CLIENT"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _ruby_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\bparams\[", "HTTP_PARAM"),
            (r"\bARGF\b", "STDIN"),
            (r"\bARGV\b", "CLI_ARG"),
            (r"\bENV\[", "ENV_VAR"),
            (r"\bgets\b", "STDIN"),
            (r"\bFile\.read\s*\(", "FILE_READ"),
            (r"\bIO\.read\s*\(", "FILE_READ"),
            (r"\bNet::HTTP\.get\s*\(", "HTTP_CLIENT"),
            (r"\bJSON\.parse\s*\(", "JSON_DESERIALIZE"),
            (r"\bYAML\.load\s*\(", "YAML_DESERIALIZE"),
            (r"\bMarshal\.load\s*\(", "DESERIALIZE"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _java_sources(self, analysis, source):
        results = []
        for pat, stype in [
            (r"\bargs\[", "CLI_ARG"),
            (r"\bSystem\.getenv\s*\(", "ENV_VAR"),
            (r"\bSystem\.in\b", "STDIN"),
            (r"\bScanner\s*\(", "STDIN"),
            (r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\(", "HTTP_ROUTE"),
            (r"\bHttpServletRequest\b", "HTTP_REQUEST"),
            (r"\b@RequestBody\b", "HTTP_BODY"),
            (r"\b@RequestParam\b", "HTTP_QUERY"),
            (r"\b@PathVariable\b", "HTTP_ROUTE_PARAM"),
            (r"\bObjectInputStream\b", "DESERIALIZE"),
            (r"\bXMLDecoder\b", "XML_DESERIALIZE"),
            (r"\bFiles\.readAllBytes\s*\(", "FILE_READ"),
        ]:
            for m in re.finditer(pat, source):
                results.append(self._make_source(analysis, source[:m.start()].count("\n") + 1, source[m.start():m.start()+80], stype))
        return results

    def _flow_confidence(self, source: TaintSource, sink: SinkMatch, analysis: FileAnalysis) -> float:
        score = 0.0
        if source.file == sink.file:
            score += 0.6
        if source.line < sink.line:
            score += 0.1

        compat = {
            ("HTTP_REQUEST", "sql_injection"): 0.3,
            ("HTTP_REQUEST", "ssrf"): 0.3,
            ("HTTP_REQUEST", "command_execution"): 0.3,
            ("HTTP_REQUEST", "deserialization"): 0.2,
            ("HTTP_REQUEST", "path_traversal"): 0.2,
            ("HTTP_REQUEST", "template_injection"): 0.2,
            ("HTTP_ROUTE", "sql_injection"): 0.3,
            ("HTTP_ROUTE", "ssrf"): 0.3,
            ("HTTP_ROUTE", "command_execution"): 0.3,
            ("HTTP_BODY", "deserialization"): 0.3,
            ("CLI_ARG", "command_execution"): 0.3,
            ("CLI_ARG", "path_traversal"): 0.3,
            ("CLI_ARG", "injection"): 0.3,
            ("STDIN", "command_execution"): 0.2,
            ("ENV_VAR", "command_execution"): 0.2,
            ("FILE_READ", "deserialization"): 0.2,
            ("FILE_READ", "path_traversal"): 0.2,
            ("KERNEL_USERSPACE", "buffer_overflow"): 0.3,
            ("KERNEL_USERSPACE", "memory"): 0.3,
            ("KERNEL_USERSPACE", "integer_overflow"): 0.2,
            ("KERNEL_USERSPACE", "race_condition"): 0.2,
            ("SYSCALL", "buffer_overflow"): 0.3,
            ("SYSCALL", "memory"): 0.3,
            ("SYSCALL", "integer_overflow"): 0.2,
            ("IOCTL", "buffer_overflow"): 0.3,
            ("IOCTL", "memory"): 0.3,
            ("PS_PARAM", "command_execution"): 0.3,
            ("PS_PARAM", "injection"): 0.3,
            ("PS_PARAM", "deserialization"): 0.2,
            ("PS_PARAM", "path_traversal"): 0.2,
            ("PS_ARGS", "command_execution"): 0.3,
            ("PS_ARGS", "injection"): 0.3,
            ("PS_STDIN", "command_execution"): 0.2,
            ("PS_INVOCATION", "command_execution"): 0.2,
            ("UNSAFE_BLOCK", "memory"): 0.3,
            ("UNSAFE_BLOCK", "ffi"): 0.2,
            ("FFI_API", "memory"): 0.2,
            ("HTTP_REQUEST", "injection"): 0.2,
            ("HTTP_REQUEST", "xxe"): 0.2,
            ("HTTP_REQUEST", "crypto"): 0.1,
        }

        score += compat.get((source.source_type, sink.category), 0.0)
        severity = {"CRITICAL": 0.3, "HIGH": 0.2, "MEDIUM": 0.1}
        score += severity.get(sink.severity, 0)
        return min(score, 1.0)
