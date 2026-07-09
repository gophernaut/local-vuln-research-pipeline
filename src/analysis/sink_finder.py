"""Sink detection — matches source code patterns against known dangerous sinks.

Based on generic-sinks.md reference. Identifies all dangerous function calls,
file operations, command execution points, deserialization, SQL query points,
etc. across supported languages.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SinkMatch:
    file: str
    line: int
    category: str
    sink_type: str
    matched_text: str
    language: str
    severity: str = "HIGH"
    cwe_id: str = ""


SINK_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "python": [
        {"category": "command_execution", "type": "os_system", "pattern": r"\bos\.system\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "os_popen", "pattern": r"\bos\.popen\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "subprocess_call", "pattern": r"\bsubprocess\.(call|run|Popen)\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "eval", "pattern": r"\beval\s*\(", "cwe": "CWE-95"},
        {"category": "command_execution", "type": "exec", "pattern": r"\bexec\s*\(", "cwe": "CWE-95"},
        {"category": "command_execution", "type": "compile_exec", "pattern": r"\bcompile\s*\(", "cwe": "CWE-95"},
        {"category": "sql_injection", "type": "raw_sql_fstring", "pattern": r"\.execute\s*\(\s*f['\"]", "cwe": "CWE-89"},
        {"category": "sql_injection", "type": "raw_sql_format", "pattern": r"""\.execute\s*\(\s*['"].*%s.*['"]""", "cwe": "CWE-89"},
        {"category": "sql_injection", "type": "cursor_execute", "pattern": r"\bcursor\.execute\s*\(", "cwe": "CWE-89"},
        {"category": "sql_injection", "type": "raw_query", "pattern": r"""\.raw\s*\(\s*['"]""", "cwe": "CWE-89"},
        {"category": "deserialization", "type": "pickle_loads", "pattern": r"\bpickle\.loads?\s*\(", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "yaml_load_unsafe", "pattern": r"\byaml\.load\s*\([^S]", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "marshal_loads", "pattern": r"\bmarshal\.loads?\s*\(", "cwe": "CWE-502"},
        {"category": "ssrf", "type": "requests_get", "pattern": r"\brequests\.(get|post|put|delete|head|patch)\s*\(", "cwe": "CWE-918"},
        {"category": "ssrf", "type": "urllib_request", "pattern": r"\burllib\.request\.(urlopen|urlretrieve)\s*\(", "cwe": "CWE-918"},
        {"category": "ssrf", "type": "httpx_request", "pattern": r"\bhttpx\.(get|post|put|delete)\s*\(", "cwe": "CWE-918"},
        {"category": "path_traversal", "type": "os_path_join_dynamic", "pattern": r"\bos\.path\.join\s*\([^)]*,", "cwe": "CWE-22"},
        {"category": "path_traversal", "type": "open_user_path", "pattern": r"\bopen\s*\(\s*[^'\"c]", "cwe": "CWE-22"},
        {"category": "file_write", "type": "open_write", "pattern": r"\bopen\s*\([^)]*['\"]w", "cwe": "CWE-73"},
        {"category": "template_injection", "type": "jinja_render", "pattern": r"\.render\s*\(.*request\b", "cwe": "CWE-1336"},
        {"category": "xxe", "type": "xml_parse_unsafe", "pattern": r"\b(etree|xml\.etree)\.(parse|fromstring)\s*\(", "cwe": "CWE-611"},
        {"category": "crypto", "type": "hardcoded_secret", "pattern": r"(?i)(secret|password|api_key|token)\s*=\s*['\"][^'\"\s]{8,}['\"]", "cwe": "CWE-798"},
    ],
    "javascript": [
        {"category": "command_execution", "type": "child_process_exec", "pattern": r"\bexec\s*\(\s*[^'\"f]", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "child_process_spawn", "pattern": r"\.spawn\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "eval_js", "pattern": r"\beval\s*\(", "cwe": "CWE-95"},
        {"category": "sql_injection", "type": "raw_query_concat", "pattern": r"\.query\s*\(\s*['\"].*\+\s", "cwe": "CWE-89"},
        {"category": "deserialization", "type": "eval_json_parse", "pattern": r"\bJSON\.parse\s*\(.*eval", "cwe": "CWE-502"},
        {"category": "ssrf", "type": "fetch_dynamic", "pattern": r"\bfetch\s*\(\s*[^'\"`/]", "cwe": "CWE-918"},
        {"category": "ssrf", "type": "axios_dynamic", "pattern": r"\baxios\.(get|post|put|delete)\s*\([^'\"`]", "cwe": "CWE-918"},
        {"category": "path_traversal", "type": "fs_readfile_dynamic", "pattern": r"\.readFile\s*\([^_]+\+", "cwe": "CWE-22"},
        {"category": "file_write", "type": "fs_writefile", "pattern": r"\.writeFile\s*\(", "cwe": "CWE-73"},
        {"category": "template_injection", "type": "ejs_render", "pattern": r"\.render\s*\(.*req\.", "cwe": "CWE-1336"},
        {"category": "crypto", "type": "hardcoded_secret", "pattern": r"(?i)(secret|password|api[_-]?key|token)\s*=\s*['\"`][^'\"`\s]{8,}['\"`]", "cwe": "CWE-798"},
        {"category": "nosql_injection", "type": "mongo_raw_query", "pattern": r"\.find\s*\(\s*\{[^}]*\$", "cwe": "CWE-943"},
        {"category": "injection", "type": "innerhtml", "pattern": r"\.innerHTML\s*=", "cwe": "CWE-79"},
    ],
    "java": [
        {"category": "command_execution", "type": "runtime_exec", "pattern": r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "processbuilder", "pattern": r"\bProcessBuilder\s*\(", "cwe": "CWE-78"},
        {"category": "sql_injection", "type": "statement_execute", "pattern": r"\.executeQuery\s*\(\s*['\"].*\+", "cwe": "CWE-89"},
        {"category": "sql_injection", "type": "jdbc_template_query", "pattern": r"\.query\s*\(\s*['\"].*\+", "cwe": "CWE-89"},
        {"category": "deserialization", "type": "objectinputstream", "pattern": r"\bObjectInputStream\b", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "xml_decoder", "pattern": r"\bXMLDecoder\b", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "yaml_load", "pattern": r"\.load\s*\([^S]", "cwe": "CWE-502"},
        {"category": "ssrf", "type": "url_openstream", "pattern": r"\.openStream\s*\(", "cwe": "CWE-918"},
        {"category": "ssrf", "type": "resttemplate", "pattern": r"\bRestTemplate\b.*\b(exchange|getForEntity|postForEntity)\b", "cwe": "CWE-918"},
        {"category": "xxe", "type": "xml_parser_unsafe", "pattern": r"\b(SAXParser|DocumentBuilder|XMLReader)\b", "cwe": "CWE-611"},
        {"category": "spel_injection", "type": "spel_parse", "pattern": r"\.parseExpression\s*\(", "cwe": "CWE-917"},
    ],
    "go": [
        {"category": "command_execution", "type": "exec_command", "pattern": r"\bexec\.Command\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "os_exec", "pattern": r"\bos\.StartProcess\s*\(", "cwe": "CWE-78"},
        {"category": "sql_injection", "type": "fmt_sprintf_query", "pattern": r"fmt\.Sprintf\s*\(\s*['\"](SELECT|INSERT|UPDATE|DELETE)", "cwe": "CWE-89"},
        {"category": "ssrf", "type": "http_get_dynamic", "pattern": r"\bhttp\.Get\s*\([^'\"`]", "cwe": "CWE-918"},
        {"category": "ssrf", "type": "http_newrequest", "pattern": r"\bhttp\.NewRequest\s*\([^,]+,[^'\"`]+(?!,)", "cwe": "CWE-918"},
        {"category": "path_traversal", "type": "os_open_user_path", "pattern": r"\bos\.Open\s*\([^'\"`\sC]", "cwe": "CWE-22"},
        {"category": "file_write", "type": "os_create", "pattern": r"\bos\.Create\s*\(", "cwe": "CWE-73"},
        {"category": "template_injection", "type": "template_execute", "pattern": r"\.Execute\s*\(.*request\b", "cwe": "CWE-1336"},
        {"category": "crypto", "type": "hardcoded_key", "pattern": r"(?i)key\s*:?=\s*['\"`][A-Za-z0-9+/=]{16,}['\"`]", "cwe": "CWE-798"},
    ],
    "c": [
        {"category": "buffer_overflow", "type": "strcpy", "pattern": r"\bstrcpy\s*\(", "cwe": "CWE-120"},
        {"category": "buffer_overflow", "type": "strcat", "pattern": r"\bstrcat\s*\(", "cwe": "CWE-120"},
        {"category": "buffer_overflow", "type": "sprintf", "pattern": r"\bsprintf\s*\(", "cwe": "CWE-120"},
        {"category": "buffer_overflow", "type": "gets", "pattern": r"\bgets\s*\(", "cwe": "CWE-120"},
        {"category": "buffer_overflow", "type": "scanf_nolimit", "pattern": r"\bscanf\s*\([^)]*%s", "cwe": "CWE-120"},
        {"category": "command_execution", "type": "system_call", "pattern": r"\bsystem\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "popen", "pattern": r"\bpopen\s*\(", "cwe": "CWE-78"},
        {"category": "format_string", "type": "printf_user", "pattern": r"\bprintf\s*\([^'\"f]", "cwe": "CWE-134"},
        {"category": "memory", "type": "malloc_no_check", "pattern": r"\bmalloc\s*\([^)]*\)\s*;[^i]", "cwe": "CWE-252"},
        {"category": "integer_overflow", "type": "malloc_multiply", "pattern": r"\bmalloc\s*\([^)]*\*\s*[^)]*\)", "cwe": "CWE-190"},
        {"category": "race_condition", "type": "toctou_fopen", "pattern": r"\baccess\s*\(.*\)\s*;.*\bfopen\s*\(.*\)", "cwe": "CWE-367"},
    ],
    "cpp": [
        {"category": "buffer_overflow", "type": "strcpy", "pattern": r"\bstrcpy\s*\(", "cwe": "CWE-120"},
        {"category": "buffer_overflow", "type": "strcat", "pattern": r"\bstrcat\s*\(", "cwe": "CWE-120"},
        {"category": "buffer_overflow", "type": "sprintf", "pattern": r"\bsprintf\s*\(", "cwe": "CWE-120"},
        {"category": "command_execution", "type": "system_call", "pattern": r"\bsystem\s*\(", "cwe": "CWE-78"},
        {"category": "format_string", "type": "printf_user", "pattern": r"\bprintf\s*\([^'\"f]", "cwe": "CWE-134"},
        {"category": "memory", "type": "new_no_delete", "pattern": r"\bnew\s+\w+[^;]*;", "cwe": "CWE-401"},
    ],
    "ruby": [
        {"category": "command_execution", "type": "system_call", "pattern": r"\bsystem\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "exec_call", "pattern": r"\bexec\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "backticks", "pattern": r"`[^`]+`", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "eval_ruby", "pattern": r"\beval\s*\(", "cwe": "CWE-95"},
        {"category": "sql_injection", "type": "where_string_interp", "pattern": r"\.where\s*\(\s*['\"]#\{", "cwe": "CWE-89"},
        {"category": "deserialization", "type": "marshal_load", "pattern": r"\bMarshal\.load\s*\(", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "yaml_load_unsafe", "pattern": r"\bYAML\.load\s*\(", "cwe": "CWE-502"},
        {"category": "ssrf", "type": "net_http", "pattern": r"\bNet::HTTP\.(get|post|start)\s*\(", "cwe": "CWE-918"},
    ],
    "csharp": [
        {"category": "command_execution", "type": "process_start", "pattern": r"\bProcess\.Start\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "powershell_create", "pattern": r"\bPowerShell\.Create\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "invoke_expression", "pattern": r"\bInvoke-Expression\b", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "add_script", "pattern": r"\.AddScript\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "add_command", "pattern": r"\.AddCommand\s*\(", "cwe": "CWE-78"},
        {"category": "sql_injection", "type": "sqlcommand_concat", "pattern": r"new SqlCommand\s*\(\s*['\"].*\+", "cwe": "CWE-89"},
        {"category": "sql_injection", "type": "raw_sql_query", "pattern": r"\.FromSqlRaw\s*\(", "cwe": "CWE-89"},
        {"category": "sql_injection", "type": "execute_sql_raw", "pattern": r"\.ExecuteSqlRaw\s*\(", "cwe": "CWE-89"},
        {"category": "deserialization", "type": "binary_formatter", "pattern": r"\bBinaryFormatter\b.*\bDeserialize\b", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "javascript_serializer", "pattern": r"\bJavaScriptSerializer\b.*\bDeserialize\b", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "json_type_name", "pattern": r"TypeNameHandling\s*=\s*TypeNameHandling\.(All|Objects|Auto)", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "xmlserializer_untrusted", "pattern": r"new XmlSerializer\(typeof\([^)]*\)\).*Deserialize", "cwe": "CWE-502"},
        {"category": "ssrf", "type": "httpclient_getstring", "pattern": r"\.GetStringAsync\s*\(", "cwe": "CWE-918"},
        {"category": "ssrf", "type": "webclient_download", "pattern": r"\bWebClient\b.*\b(DownloadString|DownloadData|DownloadFile)\b", "cwe": "CWE-918"},
        {"category": "ssrf", "type": "httpclient_send", "pattern": r"\.SendAsync\s*\(", "cwe": "CWE-918"},
        {"category": "xxe", "type": "xmldocument_load", "pattern": r"\bXmlDocument\b.*\.Load\s*\(", "cwe": "CWE-611"},
        {"category": "xxe", "type": "xmlreader_settings", "pattern": r"new XmlReaderSettings\b(?!.*DtdProcessing\s*=\s*DtdProcessing\.Prohibit)", "cwe": "CWE-611"},
        {"category": "path_traversal", "type": "path_combine_user", "pattern": r"Path\.Combine\s*\([^,]+,\s*(?!Server\.MapPath)", "cwe": "CWE-22"},
        {"category": "file_write", "type": "file_write", "pattern": r"\.(WriteAllText|WriteAllBytes|WriteAllLines)\s*\(", "cwe": "CWE-73"},
        {"category": "injection", "type": "reflection_invoke", "pattern": r"\.(InvokeMember|Invoke)\s*\([^)]*BindingFlags", "cwe": "CWE-470"},
        {"category": "crypto", "type": "hardcoded_key", "pattern": r"(?i)(password|secret|key|token)\s*=\s*\"[^\"\s]{8,}\"", "cwe": "CWE-798"},
    ],
    "powershell": [
        {"category": "command_execution", "type": "invoke_expression", "pattern": r"\bInvoke-Expression\b", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "iex", "pattern": r"\biex\b", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "invoke_command", "pattern": r"\bInvoke-Command\b", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "start_process", "pattern": r"\bStart-Process\b", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "and_operator", "pattern": r"\s&\s+\$\w+", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "dot_source", "pattern": r"\.\s+\$\w+", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "new_object_com", "pattern": r"\bNew-Object\s+-ComObject\b", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "add_type", "pattern": r"\bAdd-Type\b", "cwe": "CWE-94"},
        {"category": "deserialization", "type": "import_clixml", "pattern": r"\bImport-Clixml\b", "cwe": "CWE-502"},
        {"category": "deserialization", "type": "import_pssession", "pattern": r"\bImport-PSSession\b", "cwe": "CWE-502"},
        {"category": "injection", "type": "invoke_wmi", "pattern": r"\bInvoke-WmiMethod\b", "cwe": "CWE-78"},
        {"category": "injection", "type": "invoke_cim", "pattern": r"\bInvoke-CimMethod\b", "cwe": "CWE-78"},
        {"category": "injection", "type": "scriptblock_create", "pattern": r"\[ScriptBlock\]::Create\s*\(", "cwe": "CWE-94"},
        {"category": "injection", "type": "add_script_method", "pattern": r"\bAdd-Member\b.*-MemberType\s+ScriptMethod", "cwe": "CWE-94"},
        {"category": "path_traversal", "type": "join_path_user", "pattern": r"\bJoin-Path\b", "cwe": "CWE-22"},
        {"category": "crypto", "type": "hardcoded_cred", "pattern": r"(?i)(password|credential|secret|token|key)\s*=\s*[\"'][^\"']{6,}[\"']", "cwe": "CWE-798"},
        {"category": "crypto", "type": "securestring_misuse", "pattern": r"\bConvertTo-SecureString\b.*-AsPlainText", "cwe": "CWE-312"},
    ],
    "rust": [
        {"category": "memory", "type": "unsafe_block", "pattern": r"\bunsafe\s*\{", "cwe": "CWE-119"},
        {"category": "memory", "type": "raw_ptr_deref", "pattern": r"\*\w+\.(?:as_ptr|as_mut_ptr)\s*\(", "cwe": "CWE-119"},
        {"category": "memory", "type": "transmute", "pattern": r"\b(transmute|transmute_copy)\s*\(", "cwe": "CWE-119"},
        {"category": "memory", "type": "uninitialized", "pattern": r"\bMaybeUninit\b.*\bassume_init\s*\(", "cwe": "CWE-908"},
        {"category": "command_execution", "type": "command_new", "pattern": r"\bCommand::new\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "process_command", "pattern": r"\bstd::process::Command\b", "cwe": "CWE-78"},
        {"category": "deserialization", "type": "serde_unsafe", "pattern": r"#\[derive\(Deserialize\)\]", "cwe": "CWE-502"},
        {"category": "ffi", "type": "extern_c", "pattern": r"\bextern\s+\"C\"\b", "cwe": "CWE-119"},
        {"category": "ffi", "type": "libc_call", "pattern": r"\blibc::\w+", "cwe": "CWE-119"},
        {"category": "integer_overflow", "type": "unchecked_arith", "pattern": r"\bunchecked_\w+\s*\(", "cwe": "CWE-190"},
        {"category": "crypto", "type": "hardcoded_key", "pattern": r"(?i)(secret|key|password|token)\s*:\s*\"[^\"\s]{8,}\"", "cwe": "CWE-798"},
    ],
    "php": [
        {"category": "command_execution", "type": "system_call", "pattern": r"\bsystem\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "exec_call", "pattern": r"\bexec\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "shell_exec", "pattern": r"\bshell_exec\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "passthru", "pattern": r"\bpassthru\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "popen", "pattern": r"\bpopen\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "backticks", "pattern": r"`[^`]+`", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "proc_open", "pattern": r"\bproc_open\s*\(", "cwe": "CWE-78"},
        {"category": "command_execution", "type": "eval_php", "pattern": r"\beval\s*\(", "cwe": "CWE-95"},
        {"category": "command_execution", "type": "assert", "pattern": r"\bassert\s*\(", "cwe": "CWE-95"},
        {"category": "command_execution", "type": "create_function", "pattern": r"\bcreate_function\s*\(", "cwe": "CWE-95"},
        {"category": "command_execution", "type": "preg_replace_e", "pattern": r"\bpreg_replace\s*\(\s*[\"']/e", "cwe": "CWE-95"},
        {"category": "sql_injection", "type": "mysql_query", "pattern": r"\b(mysql_query|mysqli_query|pg_query)\s*\(\s*\$", "cwe": "CWE-89"},
        {"category": "sql_injection", "type": "query_concat", "pattern": r"->query\s*\(\s*['\"].*\.", "cwe": "CWE-89"},
        {"category": "deserialization", "type": "unserialize", "pattern": r"\bunserialize\s*\(", "cwe": "CWE-502"},
        {"category": "injection", "type": "include_var", "pattern": r"\b(include|require|include_once|require_once)\s*\$", "cwe": "CWE-98"},
        {"category": "injection", "type": "extract", "pattern": r"\bextract\s*\(", "cwe": "CWE-915"},
        {"category": "injection", "type": "parse_str", "pattern": r"\bparse_str\s*\(", "cwe": "CWE-915"},
        {"category": "path_traversal", "type": "fopen_user", "pattern": r"\b(fopen|file_get_contents|readfile)\s*\(\s*\$", "cwe": "CWE-22"},
        {"category": "xxe", "type": "simplexml_load", "pattern": r"\bsimplexml_load_(string|file)\s*\(", "cwe": "CWE-611"},
        {"category": "crypto", "type": "hardcoded_key", "pattern": r"(?i)(password|secret|api_key)\s*=\s*[\"'][^\"']{8,}[\"']", "cwe": "CWE-798"},
    ],
}


class SinkFinder:
    def __init__(self):
        self._compiled: dict[str, list[dict[str, Any]]] = {}
        for lang, patterns in SINK_PATTERNS.items():
            import re
            compiled_list = []
            for p in patterns:
                try:
                    compiled_list.append({**p, "_regex": re.compile(p["pattern"], re.IGNORECASE)})
                except re.error:
                    compiled_list.append({**p, "_regex": None})
            self._compiled[lang] = compiled_list

    def find_in_file(self, filepath: Path, language: str, source: str) -> list[SinkMatch]:
        matches = []
        patterns = self._compiled.get(language.lower(), [])
        lines = source.split("\n")

        for pattern in patterns:
            regex = pattern["_regex"]
            if regex is None:
                continue
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    matches.append(SinkMatch(
                        file=str(filepath),
                        line=i,
                        category=pattern["category"],
                        sink_type=pattern["type"],
                        matched_text=line.strip()[:120],
                        language=language,
                        cwe_id=pattern["cwe"],
                    ))

        return matches

    def find_in_directory(self, repo_path: Path) -> list[SinkMatch]:
        all_matches = []
        lang_ext_map = {
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

        for ext, lang in lang_ext_map.items():
            for filepath in repo_path.rglob(f"*{ext}"):
                if self._should_skip(filepath):
                    continue
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as f:
                        source = f.read()
                except Exception:
                    continue
                matches = self.find_in_file(filepath, lang, source)
                all_matches.extend(matches)

        return all_matches

    def _should_skip(self, path: Path) -> bool:
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                      "target", "build", "dist", "vendor", ".next", ".nuxt"}
        for part in path.parts:
            if part in skip_dirs:
                return True
        return False
