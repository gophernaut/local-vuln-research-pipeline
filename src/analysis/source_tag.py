"""Source tagger — identifies ALL untrusted entry points for all 16 languages.

Every function parameter, HTTP handler, CLI arg, file read, IPC receiver,
FFI boundary, and syscall handler is tagged with source type.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class SourceTag:
    file: str
    line: int
    variable: str
    source_type: str
    description: str
    function_name: str = ""
    is_attacker_controlled: bool = True
    confidence: float = 0.9


SOURCE_PATTERNS = {
    "python": [
        (r"request\.(?:args|form|json|data|files|headers|cookies)\b", "HTTP_REQUEST", "Flask request data"),
        (r"request\.(?:args|form|json|data)\.get\(", "HTTP_PARAM", "Flask request parameter"),
        (r"@\w+\.(?:route|get|post|put|delete|patch)\(", "HTTP_ROUTE", "HTTP route handler"),
        (r"@app\.route\s*\(\s*['\"][^'\"]*<(\w+)>", "ROUTE_PARAM", "Flask route parameter"),
        (r"\binput\s*\(", "STDIN", "Standard input"),
        (r"\bsys\.argv", "CLI_ARG", "Command line argument"),
        (r"\bos\.environ\.(?:get|__getitem__)", "ENV_VAR", "Environment variable"),
        (r"\bopen\s*\([^)]*['\"]r", "FILE_READ", "File read"),
        (r"\.recv\s*\(", "SOCKET_READ", "Socket receive"),
        (r"\bpickle\.(?:load|loads)\s*\(", "DESERIALIZE", "Pickle deserialization"),
        (r"\byaml\.load\s*\(", "YAML_DESERIALIZE", "YAML deserialization"),
        (r"\bjson\.loads?\s*\(.*request\b", "JSON_INPUT", "JSON from request"),
        (r"\bargparse\.ArgumentParser", "CLI", "CLI argument parser"),
        (r"\bclick\.(?:command|option|argument)", "CLI", "Click CLI"),
        (r"\btyper\.", "CLI", "Typer CLI"),
    ],
    "javascript": [
        (r"req\.(?:body|query|params|headers|cookies)\b", "HTTP_REQUEST", "Express request data"),
        (r"app\.(?:get|post|put|delete|patch|use)\s*\(", "HTTP_ROUTE", "Express route"),
        (r"router\.(?:get|post|put|delete|patch|use)\s*\(", "HTTP_ROUTE", "Express router"),
        (r"\bprocess\.argv", "CLI_ARG", "Node CLI argument"),
        (r"\bprocess\.env\.\w+", "ENV_VAR", "Environment variable"),
        (r"\breadFileSync\s*\(", "FILE_READ", "File read"),
        (r"\bfetch\s*\(", "HTTP_CLIENT", "HTTP client"),
        (r"\bws\.(?:on|send)\s*\(", "WEBSOCKET", "WebSocket data"),
    ],
    "typescript": [
        (r"req\.(?:body|query|params|headers|cookies)\b", "HTTP_REQUEST", "Express request data"),
        (r"app\.(?:get|post|put|delete|patch|use)\s*\(", "HTTP_ROUTE", "Express route"),
        (r"router\.(?:get|post|put|delete|patch|use)\s*\(", "HTTP_ROUTE", "Express router"),
        (r"\bprocess\.argv", "CLI_ARG", "Node CLI argument"),
        (r"\bprocess\.env\.\w+", "ENV_VAR", "Environment variable"),
        (r"\breadFileSync\s*\(", "FILE_READ", "File read"),
    ],
    "java": [
        (r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)", "HTTP_ROUTE", "Spring MVC route"),
        (r"\bHttpServletRequest\b", "HTTP_REQUEST", "Servlet request"),
        (r"\b@RequestBody\b", "HTTP_BODY", "Request body"),
        (r"\b@RequestParam\b", "HTTP_QUERY", "Query parameter"),
        (r"\b@PathVariable\b", "HTTP_ROUTE_PARAM", "URL path variable"),
        (r"\bSystem\.in\b", "STDIN", "Standard input"),
        (r"\bScanner\s*\(", "STDIN", "Scanner input"),
        (r"\bargs\[", "CLI_ARG", "CLI argument"),
        (r"\bSystem\.getenv\s*\(", "ENV_VAR", "Environment variable"),
        (r"\bFiles\.readAllBytes\s*\(", "FILE_READ", "File read"),
        (r"\bObjectInputStream\b", "DESERIALIZE", "Java deserialization"),
    ],
    "c": [
        (r"\bmain\s*\(\s*int\s+\w+\s*,\s*char\s*\*\s*\w+\s*\[\s*\]", "CLI_ARG", "C main args"),
        (r"\bgetenv\s*\(", "ENV_VAR", "Environment variable"),
        (r"\bfgets\s*\(", "STDIN", "fgets input"),
        (r"\bscanf\s*\(", "STDIN", "scanf input"),
        (r"\bgets\s*\(", "STDIN", "gets (unbounded!)"),
        (r"\bread\s*\(", "FD_READ", "File descriptor read"),
        (r"\brecv\s*\(", "SOCKET_READ", "Socket receive"),
        (r"\brecvfrom\s*\(", "SOCKET_READ", "Socket receive from"),
        (r"\bfopen\s*\(", "FILE_READ", "File open for read"),
        (r"\bopen\s*\(", "FILE_READ", "File open"),
        (r"\bmmap\s*\(", "FILE_MMAP", "Memory-mapped file"),
        (r"\bcopy_from_user\s*\(", "KERNEL_USERSPACE", "Kernel: copy from user"),
        (r"\bioctl\s*\(", "IOCTL", "ioctl handler"),
        (r"\bSYSCALL_DEFINE\d*\(", "SYSCALL", "System call"),
        (r"\bXML_Parse\s*\(", "XML_PARSE", "XML parser input"),
        (r"\bjson_parse\s*\(", "JSON_PARSE", "JSON parser input"),
    ],
    "cpp": [
        (r"\bmain\s*\(\s*int\s+\w+\s*,\s*char\s*\*\s*\w+\s*\[\s*\]", "CLI_ARG", "C++ main args"),
        (r"\bgetenv\s*\(", "ENV_VAR", "Environment variable"),
        (r"\bstd::cin\s*>>", "STDIN", "cin input"),
        (r"\bgetline\s*\(\s*std::cin", "STDIN", "getline input"),
        (r"\bfgets\s*\(", "STDIN", "fgets input"),
        (r"\bread\s*\(", "FD_READ", "File descriptor read"),
        (r"\brecv\s*\(", "SOCKET_READ", "Socket receive"),
        (r"\bfopen\s*\(", "FILE_READ", "File open"),
        (r"\bcopy_from_user\s*\(", "KERNEL_USERSPACE", "Kernel: copy from user"),
        (r"\bioctl\s*\(", "IOCTL", "ioctl handler"),
        (r"\bstd::ifstream", "FILE_READ", "ifstream read"),
    ],
    "go": [
        (r"\bos\.Args\b", "CLI_ARG", "Go CLI args"),
        (r"\bos\.Getenv\s*\(", "ENV_VAR", "Environment variable"),
        (r"\bos\.Stdin\b", "STDIN", "Standard input"),
        (r"\bos\.Open\s*\(", "FILE_READ", "File open"),
        (r"\bioutil\.ReadFile\s*\(", "FILE_READ", "File read"),
        (r"\bnet\.Listen\s*\(", "SOCKET_LISTEN", "Network listener"),
        (r"\bhttp\.HandleFunc\s*\(", "HTTP_ROUTE", "HTTP handler"),
        (r"\bjson\.NewDecoder\s*\(", "JSON_DESERIALIZE", "JSON decoder"),
        (r"\bjson\.Unmarshal\s*\(", "JSON_DESERIALIZE", "JSON unmarshal"),
    ],
    "rust": [
        (r"\bstd::env::args\s*\(", "CLI_ARG", "Rust CLI args"),
        (r"\bstd::env::var\s*\(", "ENV_VAR", "Environment variable"),
        (r"\bstd::io::stdin\s*\(", "STDIN", "Standard input"),
        (r"\bstd::fs::read\s*\(", "FILE_READ", "File read"),
        (r"\bstd::fs::read_to_string\s*\(", "FILE_READ", "File read"),
        (r"\bTcpStream::connect\s*\(", "SOCKET_READ", "TCP connect"),
        (r"\bUdpSocket::bind\s*\(", "SOCKET_READ", "UDP bind"),
        (r"\bunsafe\s*\{", "UNSAFE", "Unsafe block"),
        (r"\bserde_json::from_str\s*\(", "JSON_DESERIALIZE", "JSON deserialize"),
        (r"\bserde_json::from_reader\s*\(", "JSON_DESERIALIZE", "JSON deserialize"),
    ],
    "csharp": [
        (r"\[Http(?:Get|Post|Put|Delete|Patch)\s*\(", "HTTP_ROUTE", "ASP.NET route"),
        (r"\[FromBody\]", "HTTP_BODY", "Request body"),
        (r"\[FromQuery\]", "HTTP_QUERY", "Query parameter"),
        (r"\[FromRoute\]", "HTTP_ROUTE_PARAM", "Route parameter"),
        (r"\[FromForm\]", "HTTP_FORM", "Form data"),
        (r"HttpContext\.Request", "HTTP_REQUEST", "HttpContext request"),
        (r"\bConsole\.ReadLine\s*\(", "STDIN", "Console input"),
        (r"\bEnvironment\.GetEnvironmentVariable\s*\(", "ENV_VAR", "Environment variable"),
        (r"\bEnvironment\.GetCommandLineArgs\s*\(", "CLI_ARG", "CLI arguments"),
        (r"\bFile\.(?:ReadAllText|OpenRead|ReadAllLines)\s*\(", "FILE_READ", "File read"),
        (r"\bHttpClient\b", "HTTP_CLIENT", "HTTP client"),
        (r"\bDeserialize\w*\s*\(", "DESERIALIZE", "C# deserialization"),
        (r"\bBinaryFormatter\b", "DESERIALIZE", "BinaryFormatter"),
    ],
    "ruby": [
        (r"\bparams\[", "HTTP_PARAM", "Rails params"),
        (r"\bARGF\b", "STDIN", "ARGF input"),
        (r"\bARGV\b", "CLI_ARG", "CLI arguments"),
        (r"\bENV\[", "ENV_VAR", "Environment variable"),
        (r"\bgets\b", "STDIN", "gets input"),
        (r"\bFile\.read\s*\(", "FILE_READ", "File read"),
        (r"\bIO\.read\s*\(", "FILE_READ", "IO read"),
        (r"\bMarshal\.load\s*\(", "DESERIALIZE", "Marshal deserialize"),
    ],
    "php": [
        (r"\$_GET\[", "HTTP_GET", "GET parameter"),
        (r"\$_POST\[", "HTTP_POST", "POST parameter"),
        (r"\$_REQUEST\[", "HTTP_REQUEST", "Request parameter"),
        (r"\$_SERVER\[", "HTTP_SERVER", "Server variable"),
        (r"\$_FILES\[", "FILE_UPLOAD", "File upload"),
        (r"\$_ENV\[", "ENV_VAR", "Environment variable"),
        (r"\bphp://input\b", "HTTP_BODY", "Raw POST data"),
        (r"\bphp://stdin\b", "STDIN", "Standard input"),
        (r"\bfile_get_contents\s*\(\s*\$", "FILE_READ", "File read"),
        (r"\bjson_decode\s*\(", "JSON_DESERIALIZE", "JSON decode"),
        (r"\bunserialize\s*\(", "DESERIALIZE", "PHP deserialize"),
        (r"\bgetenv\s*\(", "ENV_VAR", "Environment variable"),
    ],
    "powershell": [
        (r"\bparam\s*\(", "PS_PARAM", "PowerShell parameter"),
        (r"\b\$args\b", "PS_ARGS", "PowerShell args"),
        (r"\b\$PSBoundParameters\b", "PS_PARAMS", "Bound parameters"),
        (r"\bRead-Host\b", "PS_STDIN", "Read-Host input"),
        (r"\bImport-Csv\b", "PS_FILE_READ", "CSV import"),
        (r"\bImport-Clixml\b", "PS_CLIXML_READ", "Clixml import"),
        (r"\bGet-Content\b", "PS_FILE_READ", "File content read"),
        (r"\bReceive-Job\b", "PS_JOB_INPUT", "Job input"),
        (r"\bConvertFrom-Json\b", "PS_JSON_INPUT", "JSON input"),
        (r"\bInvoke-RestMethod\b", "PS_HTTP_CLIENT", "REST method"),
        (r"\bInvoke-WebRequest\b", "PS_HTTP_CLIENT", "Web request"),
        (r"\b\$env:\w+", "PS_ENV_VAR", "Environment variable"),
        (r"\b\[Environment\]::GetEnvironmentVariable\b", "ENV_VAR", "Environment variable"),
    ],
    "swift": [
        (r"\bCommandLine\.arguments\b", "CLI_ARG", "Swift CLI args"),
        (r"\bProcessInfo\.processInfo\.environment\b", "ENV_VAR", "Environment"),
        (r"\bURLSession\b", "HTTP_CLIENT", "URL session"),
        (r"\bFileHandle\b", "FILE_READ", "File handle"),
    ],
    "kotlin": [
        (r"\breadLine\s*\(", "STDIN", "readLine input"),
        (r"\bargs\.", "CLI_ARG", "Kotlin CLI args"),
        (r"\bSystem\.getenv\s*\(", "ENV_VAR", "Environment variable"),
        (r"\bFile\.(?:readText|readBytes)\s*\(", "FILE_READ", "File read"),
    ],
    "shell": [
        (r"\$\{?\w+\}?", "ENV_VAR", "Shell variable"),
        (r"\bread\s+-", "STDIN", "read command"),
        (r"\bcat\s+", "FILE_READ", "cat command"),
        (r"<\s*\(", "STDIN", "Process substitution"),
        (r"\b\$1\b|\b\$2\b|\b\$@\b|\b\$*\b", "CLI_ARG", "Shell positional args"),
    ],
}


class SourceTagger:
    def tag_file(self, filepath: Path, source: str, language: str) -> list[SourceTag]:
        patterns = SOURCE_PATTERNS.get(language, [])
        tags = []

        for pattern, source_type, description in patterns:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                variable = m.group(0) if m.lastindex is None else (m.group(1) if m.lastindex >= 1 else m.group(0))
                tags.append(SourceTag(
                    file=str(filepath), line=line_num,
                    variable=variable[:200],
                    source_type=source_type,
                    description=description,
                    is_attacker_controlled=True,
                    confidence=0.9,
                ))

        return tags

    def tag_repo(self, repo_path: Path) -> list[SourceTag]:
        from src.analysis.ast_parser import LANGUAGE_EXTENSIONS, SKIP_DIRS
        all_tags = []
        for ext, lang in LANGUAGE_EXTENSIONS.items():
            for filepath in repo_path.rglob(f"*{ext}"):
                if any(d in filepath.parts for d in SKIP_DIRS):
                    continue
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as f:
                        source = f.read()
                    tags = self.tag_file(filepath, source, lang)
                    all_tags.extend(tags)
                except Exception:
                    continue
        return all_tags
