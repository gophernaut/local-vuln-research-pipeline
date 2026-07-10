"""Sanitizer tagger — identifies all sanitizers, validators, and auth checks.

A sanitizer is any code that:
- Validates input (whitelist, regex, type check, range check)
- Sanitizes output (encoding, escaping, stripping, canonicalization)
- Enforces access control (auth check, permission, ownership)
- Uses a safe API (parameterized query, prepared statement, safe_join)
- Performs bounds checking (length check, size validation)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class SanitizerTag:
    file: str
    line: int
    category: str
    function_name: str
    description: str
    protected_against: list[str] = field(default_factory=list)
    is_effective: bool = True


SANITIZER_PATTERNS = {
    "python": [
        (r"\bhtml\.escape\s*\(", "encoding", ["xss", "html_injection"]),
        (r"\bmarkupsafe\.escape\s*\(", "encoding", ["xss", "html_injection"]),
        (r"\bbleach\.clean\s*\(", "sanitization", ["xss"]),
        (r"\bDOMPurify\.sanitize\s*\(", "sanitization", ["xss"]),
        (r"\bshlex\.quote\s*\(", "shell_escape", ["command_injection"]),
        (r"\bquote\s*\(", "shell_escape", ["command_injection"]),
        (r"\bos\.path\.realpath\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bPath\.resolve\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bsecure_filename\s*\(", "path_sanitization", ["path_traversal"]),
        (r"\byaml\.safe_load\s*\(", "safe_deserialize", ["deserialization"]),
        (r"\bint\s*\(", "type_conversion", ["type_confusion"]),
        (r"\bfloat\s*\(", "type_conversion", ["type_confusion"]),
        (r"\bif\s+isinstance\s*\(", "type_check", ["type_confusion"]),
        (r"\bre\.match\s*\(", "validation", ["format_string", "command_injection"]),
        (r"\bre\.fullmatch\s*\(", "validation", ["format_string"]),
        (r"\bre\.search\s*\(", "validation", ["format_string"]),
        (r"\bFlask\.login\s*\.\s*current_user\.is_authenticated", "auth_check", ["auth_bypass"]),
        (r"@login_required", "auth_check", ["auth_bypass"]),
        (r"@permission_required", "auth_check", ["privilege_escalation"]),
        (r"@admin_required", "auth_check", ["privilege_escalation"]),
        (r"@jwt_required", "auth_check", ["auth_bypass"]),
        (r"@requires_auth", "auth_check", ["auth_bypass"]),
        (r"\bcsrf\.exempt\b", "csrf_check", ["csrf"]),
        (r"\bif\s+len\s*\(.*\)\s*[<>]=?\s*\d+", "length_check", ["buffer_overflow"]),
        (r"\bPreparedStatement\b", "parameterized_query", ["sql_injection"]),
    ],
    "javascript": [
        (r"\bDOMPurify\.sanitize\s*\(", "sanitization", ["xss"]),
        (r"\bsanitize-html\s*\(", "sanitization", ["xss"]),
        (r"\bxss\s*\(", "sanitization", ["xss"]),
        (r"\bvalidator\.isEmail\s*\(", "validation", ["type_confusion"]),
        (r"\bvalidator\.isURL\s*\(", "validation", ["ssrf"]),
        (r"\bvalidator\.isIP\s*\(", "validation", ["ssrf"]),
        (r"\bvalidator\.isInt\s*\(", "validation", ["type_confusion"]),
        (r"\bvalidator\.isFloat\s*\(", "validation", ["type_confusion"]),
        (r"\bpath\.normalize\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bpath\.resolve\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bshellexec\.quote\s*\(", "shell_escape", ["command_injection"]),
        (r"\bescape-html\s*\(", "encoding", ["xss"]),
        (r"\bjsonschema\.validate\s*\(", "schema_validation", ["type_confusion"]),
        (r"\bjwt\.verify\s*\(", "auth_check", ["auth_bypass"]),
        (r"\bjwt\.decode\s*\(", "auth_check", ["auth_bypass"]),
        (r"\bmiddleware\.authenticate\s*\(", "auth_check", ["auth_bypass"]),
        (r"\bif\s+.*\.length\s*[<>]=?\s*\d+", "length_check", ["buffer_overflow"]),
        (r"\.escape\s*\(", "encoding", ["xss", "sql_injection"]),
        (r"encodeURIComponent\s*\(", "url_encoding", ["xss", "ssrf"]),
        (r"\.parameterized\b", "parameterized_query", ["sql_injection"]),
    ],
    "typescript": [
        (r"\bDOMPurify\.sanitize\s*\(", "sanitization", ["xss"]),
        (r"\bsanitize-html\s*\(", "sanitization", ["xss"]),
        (r"\bvalidator\.isEmail\s*\(", "validation", ["type_confusion"]),
        (r"\bvalidator\.isURL\s*\(", "validation", ["ssrf"]),
        (r"\bpath\.normalize\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bpath\.resolve\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\.escape\s*\(", "encoding", ["xss", "sql_injection"]),
        (r"encodeURIComponent\s*\(", "url_encoding", ["xss", "ssrf"]),
    ],
    "java": [
        (r"\bStringEscapeUtils\.escapeHtml\s*\(", "encoding", ["xss"]),
        (r"\bStringEscapeUtils\.escapeXml\s*\(", "encoding", ["xxe"]),
        (r"\bStringEscapeUtils\.escapeSql\s*\(", "encoding", ["sql_injection"]),
        (r"\bHtmlUtils\.htmlEscape\s*\(", "encoding", ["xss"]),
        (r"\bESAPI\.encoder\(\)\.encodeForHTML", "encoding", ["xss"]),
        (r"\bESAPI\.encoder\(\)\.encodeForSQL", "encoding", ["sql_injection"]),
        (r"\bESAPI\.encoder\(\)\.encodeForOSCommand", "encoding", ["command_injection"]),
        (r"\bPreparedStatement\b", "parameterized_query", ["sql_injection"]),
        (r"\bsetString\s*\(", "parameterized_value", ["sql_injection"]),
        (r"\bPath\.normalize\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bFiles\.isReadable\s*\(", "access_check", ["path_traversal"]),
        (r"\b@PreAuthorize\s*\(", "auth_check", ["auth_bypass"]),
        (r"\b@Secured\s*\(", "auth_check", ["auth_bypass"]),
        (r"\b@RolesAllowed\s*\(", "auth_check", ["privilege_escalation"]),
        (r"\bValidator\.validateEmail\s*\(", "validation", ["type_confusion"]),
        (r"\bValidator\.validateURL\s*\(", "validation", ["ssrf"]),
        (r"\bInputValidationException\b", "validation", ["type_confusion"]),
    ],
    "c": [
        (r"\bsnprintf\s*\([^,]+,\s*sizeof", "bounds_check", ["buffer_overflow"]),
        (r"\bstrncpy\s*\([^,]+,\s*[^,]+,\s*sizeof", "bounds_check", ["buffer_overflow"]),
        (r"\bstrlcpy\s*\(", "safe_string", ["buffer_overflow"]),
        (r"\bstrlcat\s*\(", "safe_string", ["buffer_overflow"]),
        (r"\bif\s*\(.*\)\s*<", "length_check", ["buffer_overflow"]),
        (r"\bif\s*\(.*\)\s*<=\s*sizeof", "bounds_check", ["buffer_overflow"]),
        (r"\bcanReadFile\s*\(", "access_check", ["path_traversal"]),
        (r"\bisPathSafe\s*\(", "access_check", ["path_traversal"]),
        (r"\bif\s*\(.*[<>]\s*SIZE_MAX", "overflow_check", ["integer_overflow"]),
        (r"\b__builtin_mul_overflow\s*\(", "overflow_check", ["integer_overflow"]),
        (r"\b__builtin_add_overflow\s*\(", "overflow_check", ["integer_overflow"]),
        (r"\bbounds_check\b", "bounds_check", ["buffer_overflow"]),
    ],
    "cpp": [
        (r"\bstd::string::append\s*\([^,]+,\s*\d+\)", "bounds_check", ["buffer_overflow"]),
        (r"\bstrncpy_s\s*\(", "safe_string", ["buffer_overflow"]),
        (r"\bstrncat_s\s*\(", "safe_string", ["buffer_overflow"]),
        (r"\bsnprintf\s*\(", "bounds_check", ["buffer_overflow"]),
        (r"\bboost::filesystem::canonical\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bif\s*\(.*\)\s*<", "length_check", ["buffer_overflow"]),
        (r"\bstd::regex_match\s*\(", "validation", ["format_string"]),
    ],
    "go": [
        (r"\bhtml\.EscapeString\s*\(", "encoding", ["xss"]),
        (r"\bhtml\.UnescapeString\s*\(", "encoding", ["xss"]),
        (r"\btemplate\.HTMLEscapeString\s*\(", "encoding", ["xss"]),
        (r"\bfilepath\.Clean\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bfilepath\.EvalSymlinks\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bshellescape\.Quote\s*\(", "shell_escape", ["command_injection"]),
        (r"\burl\.QueryEscape\s*\(", "url_encoding", ["xss", "ssrf"]),
        (r"\bdb\.Query\s*\(\s*[\"'].*[\"'],\s*", "parameterized_query", ["sql_injection"]),
        (r"\bif\s+len\s*\(.*\)\s*[<>]\s*\d+", "length_check", ["buffer_overflow"]),
        (r"\bvalidator\.ValidateEmail\s*\(", "validation", ["type_confusion"]),
    ],
    "rust": [
        (r"\bString::from_utf8_lossy\s*\(", "encoding", ["format_string"]),
        (r"\bString::from_utf8\s*\(", "encoding", ["format_string"]),
        (r"\bvalidate_email\s*\(", "validation", ["type_confusion"]),
        (r"\bvalidate_url\s*\(", "validation", ["ssrf"]),
        (r"\bPathBuf::canonicalize\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bPath::canonicalize\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bshell_escape\s*\(", "shell_escape", ["command_injection"]),
        (r"\bhtml_escape\s*\(", "encoding", ["xss"]),
        (r"\bif\s+.*\.len\s*\(\)\s*[<>]=?\s*\d+", "length_check", ["buffer_overflow"]),
    ],
    "csharp": [
        (r"\bHttpUtility\.HtmlEncode\s*\(", "encoding", ["xss"]),
        (r"\bWebUtility\.HtmlEncode\s*\(", "encoding", ["xss"]),
        (r"\bAntiXssEncoder\.HtmlEncode\s*\(", "encoding", ["xss"]),
        (r"\bAntiXss\.HtmlEncode\s*\(", "encoding", ["xss"]),
        (r"\bPath\.GetFullPath\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bif\s*\(.*\.Length\s*[<>]\s*\d+\)", "length_check", ["buffer_overflow"]),
        (r"@\[Authorize\s*\(", "auth_check", ["auth_bypass"]),
        (r"@\[ValidateInput", "input_validation", ["xss", "sql_injection"]),
        (r"\bSqlParameter\s*\(", "parameterized_query", ["sql_injection"]),
        (r"\bRegex\.IsMatch\s*\(", "validation", ["format_string"]),
        (r"\bRegex\.Match\s*\(", "validation", ["format_string"]),
    ],
    "ruby": [
        (r"\bERB::Util\.html_escape\s*\(", "encoding", ["xss"]),
        (r"\bERB::Util\.url_encode\s*\(", "encoding", ["xss"]),
        (r"\bCGI\.escapeHTML\s*\(", "encoding", ["xss"]),
        (r"\bShellwords\.escape\s*\(", "shell_escape", ["command_injection"]),
        (r"\bFile\.expand_path\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bFile\.realpath\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bvalidates\s+:.*format", "validation", ["format_string"]),
        (r"\bbefore_action\s+:authenticate", "auth_check", ["auth_bypass"]),
        (r"\bbefore_filter\s+:authenticate", "auth_check", ["auth_bypass"]),
        (r"\bauthenticate_user!\s*\(", "auth_check", ["auth_bypass"]),
    ],
    "php": [
        (r"\bhtmlspecialchars\s*\(", "encoding", ["xss"]),
        (r"\bhtmlentities\s*\(", "encoding", ["xss"]),
        (r"\bmysqli_real_escape_string\s*\(", "encoding", ["sql_injection"]),
        (r"\bmysql_real_escape_string\s*\(", "encoding", ["sql_injection"]),
        (r"\bpg_escape_string\s*\(", "encoding", ["sql_injection"]),
        (r"\bfilter_var\s*\(\s*[^,]+,\s*FILTER_VALIDATE_EMAIL", "validation", ["type_confusion"]),
        (r"\bfilter_var\s*\(\s*[^,]+,\s*FILTER_VALIDATE_URL", "validation", ["ssrf"]),
        (r"\bfilter_var\s*\(\s*[^,]+,\s*FILTER_VALIDATE_IP", "validation", ["ssrf"]),
        (r"\bfilter_var\s*\(\s*[^,]+,\s*FILTER_VALIDATE_INT", "validation", ["type_confusion"]),
        (r"\bfilter_input\s*\(", "input_validation", ["type_confusion"]),
        (r"\bprepared_statement\s*\(", "parameterized_query", ["sql_injection"]),
        (r"\bPDO::prepare\s*\(", "parameterized_query", ["sql_injection"]),
        (r"\bAuth::check\s*\(", "auth_check", ["auth_bypass"]),
        (r"\bGate::allows\s*\(", "auth_check", ["auth_bypass"]),
        (r"\b\?\>.*?<\?php", "php_block", []),
    ],
    "powershell": [
        (r"\bConvertTo-Json\s*\-Depth\s*\d+", "serialization", []),
        (r"\bTest-Path\s*\(", "path_check", ["path_traversal"]),
        (r"\bResolve-Path\s*\(", "path_canonicalization", ["path_traversal"]),
        (r"\bGet-AuthenticodeSignature\s*\(", "signature_check", ["code_injection"]),
        (r"\bStart-Process\s*\-Credential", "credential_use", ["auth_bypass"]),
        (r"\bNew-SelfSignedCertificate\b", "crypto", ["weak_crypto"]),
    ],
}


class SanitizerTagger:
    def tag_file(self, filepath: Path, source: str, language: str) -> list[SanitizerTag]:
        patterns = SANITIZER_PATTERNS.get(language, [])
        tags = []
        for pattern, category, protected in patterns:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                func_name = m.group(0) if m.lastindex is None else m.group(0)
                tags.append(SanitizerTag(
                    file=str(filepath), line=line_num,
                    category=category, function_name=func_name[:100],
                    description=f"Sanitizer: {category}",
                    protected_against=protected,
                    is_effective=True,
                ))
        return tags

    def tag_repo(self, repo_path: Path) -> list[SanitizerTag]:
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
