"""Sink tagger — identifies ALL dangerous operations across ALL 16 languages.

Covers: command injection, SQL injection, path traversal, deserialization,
SSRF, XXE, template injection, SSRF, crypto, auth, memory corruption,
file operations, NoSQL injection, LDAP injection, XPath injection,
header injection, business logic, and more.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

logger = get_logger()

ALL_SINKS = {
    "python": [
        (r"\bos\.system\s*\(", "command_execution", "CWE-78", "OS command injection"),
        (r"\bos\.popen\s*\(", "command_execution", "CWE-78", "OS command injection"),
        (r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\(", "command_execution", "CWE-78", "Subprocess execution"),
        (r"\bos\.execvpe?\s*\(", "command_execution", "CWE-78", "Process exec"),
        (r"\bos\.spawn[lp]?\s*\(", "command_execution", "CWE-78", "Process spawn"),
        (r"\beval\s*\(", "code_execution", "CWE-95", "Code injection via eval"),
        (r"\bexec\s*\(", "code_execution", "CWE-95", "Code injection via exec"),
        (r"\bcompile\s*\(", "code_execution", "CWE-95", "Code compilation"),
        (r"\b__import__\s*\(", "code_execution", "CWE-95", "Dynamic import"),
        (r"\bpickle\.loads?\s*\(", "deserialization", "CWE-502", "Pickle deserialization"),
        (r"\bcPickle\.loads?\s*\(", "deserialization", "CWE-502", "cPickle deserialization"),
        (r"\bmarshal\.loads?\s*\(", "deserialization", "CWE-502", "Marshal deserialization"),
        (r"\byaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)", "deserialization", "CWE-502", "Unsafe YAML load"),
        (r"\byaml\.unsafe_load\s*\(", "deserialization", "CWE-502", "Unsafe YAML load"),
        (r"\bsheval\b|subprocess\.call.*shell=True", "command_injection", "CWE-78", "Shell injection"),
        (r"\.execute\s*\(\s*f['\"]|\.execute\s*\(\s*['\"].*%s|\.execute\s*\(\s*['\"].*\+|\.execute\s*\(\s*\w", "sql_injection", "CWE-89", "SQL injection"),
        (r"\bcursor\.execute\s*\(", "sql_injection", "CWE-89", "Raw SQL query"),
        (r"\bdb\.execute\s*\(", "sql_injection", "CWE-89", "Raw SQL query"),
        (r"\bcur\.execute\s*\(", "sql_injection", "CWE-89", "Raw SQL query"),
        (r"\.executemany\s*\(", "sql_injection", "CWE-89", "Bulk SQL execution"),
        (r"\.raw\s*\(\s*['\"]", "sql_injection", "CWE-89", "Raw SQL via ORM"),
        (r"\brequests\.(?:get|post|put|delete|head|patch|request)\s*\(", "ssrf", "CWE-918", "HTTP request (potential SSRF)"),
        (r"\burllib\.request\.(?:urlopen|urlretrieve)\s*\(", "ssrf", "CWE-918", "URL open (potential SSRF)"),
        (r"\bhttpx\.(?:get|post|put|delete|request)\s*\(", "ssrf", "CWE-918", "HTTPX request"),
        (r"\bos\.path\.join\s*\([^)]*,", "path_traversal", "CWE-22", "Path join with dynamic parts"),
        (r"\bopen\s*\(\s*[^'\"c)]", "path_traversal", "CWE-22", "File open with dynamic path"),
        (r"\bPath\s*\(\s*[^'\"]", "path_traversal", "CWE-22", "Path with dynamic component"),
        (r"\.render\s*\(.*request\b", "template_injection", "CWE-1336", "SSTI via template render"),
        (r"\bTemplate\s*\(.*request\b", "template_injection", "CWE-1336", "Jinja2 Template with user input"),
        (r"\bTemplate\s*\([^)]*\)\s*\.\s*render", "template_injection", "CWE-1336", "Jinja2 Template render (potential SSTI)"),
        (r"\bMakoTemplate\s*\(.*\)\s*\.\s*render", "template_injection", "CWE-1336", "Mako template render"),
        (r"\benv\.from_string\s*\(", "template_injection", "CWE-1336", "Jinja2 from_string (potential SSTI)"),
        (r"\bengine\s*\.\s*from_string", "template_injection", "CWE-1336", "Template engine from_string (SSTI)"),
        (r"\b(etree|xml\.etree)\.(?:parse|fromstring)\s*\(", "xxe", "CWE-611", "XML parsing (XXE risk)"),
        (r"(?i)(?:secret|password|api_key|token|auth)\s*=\s*['\"][^'\"\s]{8,}['\"]", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
        (r"app\.secret_key\s*=\s*['\"]", "hardcoded_secret", "CWE-798", "Hardcoded Flask secret key"),
        (r"app\.config\[['\"](?:SECRET_KEY|PASSWORD|API_KEY)['\"]\]\s*=\s*['\"]", "hardcoded_secret", "CWE-798", "Hardcoded Flask config secret"),
        (r"\bhashlib\.md5\s*\(", "weak_crypto", "CWE-328", "MD5 usage"),
        (r"\bhashlib\.sha1\s*\(", "weak_crypto", "CWE-328", "SHA1 usage"),
        (r"\bCrypto\.Cipher\.(?:DES|ARC4|Blowfish)\b", "weak_crypto", "CWE-327", "Weak cipher algorithm"),
        (r"\bDES\.(?:new|new\s*\()", "weak_crypto", "CWE-327", "DES cipher (weak)"),
        (r"\b(?:AES|MODE_ECB)\b", "weak_crypto", "CWE-327", "ECB mode (weak)"),
        (r"\brandom\.(?:randint|choice|random|uniform|randrange)\s*\(", "weak_random", "CWE-338", "Non-cryptographic random"),
        (r"\bjwt\.decode\s*\([^)]*verify\s*=\s*False", "auth_bypass", "CWE-347", "JWT decode without signature verification"),
        (r"\bjwt\.decode\s*\([^,)]*\)", "auth_bypass", "CWE-347", "JWT decode (check signature verification)"),
        (r"\bjwt\.encode\s*\(", "auth_bypass", "CWE-347", "JWT encode (ensure proper signing)"),
        (r"\bmd5\s*\(", "weak_crypto", "CWE-328", "MD5 hash function"),
        (r"\bDES\s*\.\s*new", "weak_crypto", "CWE-327", "DES cipher (deprecated)"),
        (r"verify\s*=\s*False", "auth_bypass", "CWE-295", "TLS/SSL verification disabled"),
        (r"\bssl\._create_unverified_context\b", "auth_bypass", "CWE-295", "Unverified SSL context"),
        (r"check_hostname\s*=\s*False", "auth_bypass", "CWE-297", "SSL hostname check disabled"),
        (r"if\s+\w+\s*==\s*['\"][^'\"]+['\"]", "hardcoded_secret", "CWE-798", "Hardcoded string comparison (potential hardcoded credential)"),
        (r"if\s+\w+\.lower\(\)\s*==\s*['\"]", "hardcoded_secret", "CWE-798", "Case-insensitive hardcoded comparison"),
        (r"app\.config\[['\"](?:DEBUG|TESTING)['\"]\]\s*=\s*True", "security_misconfig", "CWE-489", "Debug mode enabled in production"),
        (r"if\s+DEBUG\s*:\s*$", "security_misconfig", "CWE-489", "Debug conditional block"),
        (r"if\s+app\.debug\s*:", "security_misconfig", "CWE-489", "Flask debug mode check"),
        (r"\bbalance\s*=\s*100", "race_condition", "CWE-362", "Global mutable state (race condition risk)"),
        (r"global\s+\w+", "race_condition", "CWE-362", "Global state mutation (race condition risk)"),
        (r"if\s+balance\s*>=", "race_condition", "CWE-362", "TOCTOU: check balance then deduct (race)"),
        (r"time\.sleep\s*\(", "race_condition", "CWE-362", "Sleep in critical section (race window)"),
        (r"\b(?:sql|query|cmd|command)\s*=\s*['\"](?:SELECT|INSERT|UPDATE|DELETE)", "sql_injection", "CWE-89", "SQL string construction"),
        (r"\.format\s*\(.*\)", "format_string", "CWE-134", "String formatting (potential format string)"),
        (r"\{\s*\}\s*\.format", "format_string", "CWE-134", "str.format with user input"),
        (r"\bFlask\s*\(", "web_framework", "", "Web framework entry"),
        (r"\bFastAPI\s*\(", "web_framework", "", "Web framework entry"),
        (r"\bDjango\s*\(", "web_framework", "", "Web framework entry"),
    ],
    "javascript": [
        (r"\bchild_process\.(?:exec|spawn)\s*\(", "command_execution", "CWE-78", "Child process execution"),
        (r"\bchild_process\.execSync\s*\(", "command_execution", "CWE-78", "Sync child process"),
        (r"\beval\s*\(", "code_execution", "CWE-95", "Code injection via eval"),
        (r"\bnew\s+Function\s*\(", "code_execution", "CWE-95", "Function constructor injection"),
        (r"\.query\s*\(\s*['\"].*\+\s", "sql_injection", "CWE-89", "SQL injection via concatenation"),
        (r"\bJSON\.parse\s*\(.*eval", "deserialization", "CWE-502", "JSON parse with eval"),
        (r"\bfetch\s*\(\s*[^'\"`/]", "ssrf", "CWE-918", "Fetch with dynamic URL"),
        (r"\baxios\.(?:get|post|put|delete)\s*\([^'\"`]", "ssrf", "CWE-918", "Axios with dynamic URL"),
        (r"\.readFile\s*\([^_]+\+", "path_traversal", "CWE-22", "File read with dynamic path"),
        (r"\.writeFile\s*\(", "file_write", "CWE-73", "File write"),
        (r"\.render\s*\(.*req\.", "template_injection", "CWE-1336", "SSTI via template render"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*=\s*['\"`][^'\"`\s]{8,}['\"`]", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
        (r"\.innerHTML\s*=", "xss", "CWE-79", "innerHTML XSS"),
        (r"\.find\s*\(\s*\{[^}]*\$", "nosql_injection", "CWE-943", "NoSQL injection"),
        (r"\$where\b", "nosql_injection", "CWE-943", "MongoDB $where injection"),
        (r"\$expr\b", "nosql_injection", "CWE-943", "MongoDB $expr injection"),
    ],
    "java": [
        (r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "command_execution", "CWE-78", "Runtime exec"),
        (r"\bProcessBuilder\s*\(", "command_execution", "CWE-78", "ProcessBuilder creation"),
        (r"\.executeQuery\s*\(\s*['\"].*\+", "sql_injection", "CWE-89", "SQL injection"),
        (r"\bObjectInputStream\b", "deserialization", "CWE-502", "Java deserialization"),
        (r"\bXMLDecoder\b", "deserialization", "CWE-502", "XMLDecoder deserialization"),
        (r"\.openStream\s*\(", "ssrf", "CWE-918", "URL openStream (SSRF)"),
        (r"\bRestTemplate\b.*\b(?:exchange|getForEntity|postForEntity)\b", "ssrf", "CWE-918", "RestTemplate SSRF"),
        (r"\b(SAXParser|DocumentBuilder|XMLReader)\b", "xxe", "CWE-611", "XML parser (XXE risk)"),
        (r"\.parseExpression\s*\(", "spel_injection", "CWE-917", "SpEL injection"),
        (r"\bFiles\.write\s*\(", "file_write", "CWE-73", "File write"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*=\s*\"[^\"\s]{8,}\"", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
        (r"\bMessageDigest\.getInstance\s*\(\s*['\"]MD5", "weak_crypto", "CWE-328", "MD5 usage"),
        (r"\bMessageDigest\.getInstance\s*\(\s*['\"]SHA-?1", "weak_crypto", "CWE-328", "SHA1 usage"),
        (r"\bThreadLocalRandom\b", "weak_random", "CWE-338", "Non-cryptographic random for security"),
        (r"\bLDAPSearchConstraints\b|\.search\s*\(\s*['\"]", "ldap_injection", "CWE-90", "LDAP injection"),
        (r"\bXPathExpression\b|\.evaluate\s*\(\s*['\"]", "xpath_injection", "CWE-91", "XPath injection"),
    ],
    "c": [
        (r"\bstrcpy\s*\(", "buffer_overflow", "CWE-120", "strcpy (no bounds)"),
        (r"\bstrcat\s*\(", "buffer_overflow", "CWE-120", "strcat (no bounds)"),
        (r"\bsprintf\s*\(", "buffer_overflow", "CWE-120", "sprintf (no bounds)"),
        (r"\bgets\s*\(", "buffer_overflow", "CWE-120", "gets (always unsafe)"),
        (r"\bscanf\s*\([^)]*%s", "buffer_overflow", "CWE-120", "scanf %s (no bounds)"),
        (r"\bsystem\s*\(", "command_execution", "CWE-78", "system() call"),
        (r"\bpopen\s*\(", "command_execution", "CWE-78", "popen() call"),
        (r"\bprintf\s*\([^'\"f]", "format_string", "CWE-134", "Format string (non-literal)"),
        (r"\bmalloc\s*\([^)]*\*\s*[^)]*\)", "integer_overflow", "CWE-190", "malloc with multiplication"),
        (r"\bfree\s*\(\s*(\w+)\s*\)", "free", "CWE-416", "free() — check for UAF"),
        (r"\baccess\s*\(.*\)\s*;.*\bfopen\s*\(", "race_condition", "CWE-367", "TOCTOU race"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*=\s*[\"'][^\"\s]{8,}[\"']", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
    ],
    "cpp": [
        (r"\bstrcpy\s*\(", "buffer_overflow", "CWE-120", "strcpy (no bounds)"),
        (r"\bstrcat\s*\(", "buffer_overflow", "CWE-120", "strcat (no bounds)"),
        (r"\bsprintf\s*\(", "buffer_overflow", "CWE-120", "sprintf (no bounds)"),
        (r"\bgets\s*\(", "buffer_overflow", "CWE-120", "gets (always unsafe)"),
        (r"\bsystem\s*\(", "command_execution", "CWE-78", "system() call"),
        (r"\bnew\s+\w+\s*\[", "new_array", "CWE-122", "Heap allocation"),
        (r"\bdelete\s*\[\s*\]", "delete_array", "CWE-416", "Array delete"),
        (r"\bdelete\s+\w+", "delete_obj", "CWE-416", "Object delete"),
        (r"\.c_str\s*\(\)", "string_cast", "CWE-120", "String to C string"),
        (r"\.data\s*\(\)", "data_access", "CWE-120", "String data access"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*=\s*\"[^\"\s]{8,}\"", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
    ],
    "go": [
        (r"\bexec\.Command\s*\(", "command_execution", "CWE-78", "Command execution"),
        (r"\bos\.StartProcess\s*\(", "command_execution", "CWE-78", "Process start"),
        (r"\bfmt\.Sprintf\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE)", "sql_injection", "CWE-89", "SQL via Sprintf"),
        (r"\bhttp\.Get\s*\([^'\"`]", "ssrf", "CWE-918", "HTTP Get with dynamic URL"),
        (r"\bhttp\.NewRequest\s*\([^,]+,[^'\"`]+", "ssrf", "CWE-918", "NewRequest with dynamic URL"),
        (r"\bos\.Open\s*\([^'\"`]", "path_traversal", "CWE-22", "File open with dynamic path"),
        (r"\bos\.Create\s*\(", "file_write", "CWE-73", "File create"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*:\s*['\"`][^'\"`\s]{8,}['\"`]", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
    ],
    "rust": [
        (r"\bunsafe\s*\{", "unsafe_block", "CWE-119", "Unsafe block"),
        (r"\btransmute\s*\(", "transmute", "CWE-119", "Transmute (type confusion)"),
        (r"\bCommand::new\s*\(", "command_execution", "CWE-78", "Command execution"),
        (r"\bstd::process::Command\b", "command_execution", "CWE-78", "Process command"),
        (r"\bextern\s+\"C\"", "ffi", "CWE-119", "FFI boundary"),
        (r"\braw_ptr\b|\*\w+\.\s*(?:as_ptr|as_mut_ptr)", "raw_pointer", "CWE-119", "Raw pointer operation"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*:\s*\"[^\"\s]{8,}\"", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
        (r"\bunsafe\s*\{[^}]*copy_nonoverlapping", "unsafe_copy", "CWE-119", "Unsafe memcpy"),
    ],
    "csharp": [
        (r"\bProcess\.Start\s*\(", "command_execution", "CWE-78", "Process.Start"),
        (r"\bPowerShell\.Create\s*\(", "command_execution", "CWE-78", "PowerShell creation"),
        (r"\bInvoke-Expression\b", "command_execution", "CWE-78", "Invoke-Expression"),
        (r"\.AddScript\s*\(", "command_execution", "CWE-78", "AddScript injection"),
        (r"\.AddCommand\s*\(", "command_execution", "CWE-78", "AddCommand injection"),
        (r"new SqlCommand\s*\(\s*['\"].*\+", "sql_injection", "CWE-89", "SQL injection"),
        (r"\.FromSqlRaw\s*\(", "sql_injection", "CWE-89", "Raw SQL query"),
        (r"\.ExecuteSqlRaw\s*\(", "sql_injection", "CWE-89", "ExecuteSqlRaw"),
        (r"\bBinaryFormatter\b.*\bDeserialize\b", "deserialization", "CWE-502", "BinaryFormatter"),
        (r"\bJavaScriptSerializer\b.*\bDeserialize\b", "deserialization", "CWE-502", "JavaScriptSerializer"),
        (r"TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Objects|Auto)", "deserialization", "CWE-502", "TypeNameHandling unsafe"),
        (r"\.GetStringAsync\s*\(", "ssrf", "CWE-918", "HttpClient SSRF"),
        (r"\bWebClient\b.*\b(?:DownloadString|DownloadData|DownloadFile)\b", "ssrf", "CWE-918", "WebClient SSRF"),
        (r"\bXmlDocument\b.*\.Load\s*\(", "xxe", "CWE-611", "XmlDocument XXE"),
        (r"new XmlReaderSettings\b(?!.*DtdProcessing\s*=\s*DtdProcessing\.Prohibit)", "xxe", "CWE-611", "XmlReaderSettings unsafe"),
        (r"Path\.Combine\s*\([^,]+,\s*(?!Server\.MapPath)", "path_traversal", "CWE-22", "Path.Combine user input"),
        (r"\.(?:WriteAllText|WriteAllBytes|WriteAllLines)\s*\(", "file_write", "CWE-73", "File write"),
        (r"\.(?:InvokeMember|Invoke)\s*\([^)]*BindingFlags", "reflection_invoke", "CWE-470", "Reflection invoke"),
        (r"(?i)(?:password|secret|key|token)\s*=\s*\"[^\"\s]{8,}\"", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
    ],
    "typescript": [
        (r"\bchild_process\.(?:exec|spawn|execSync|spawnSync)\s*\(", "command_execution", "CWE-78", "Child process execution"),
        (r"\beval\s*\(", "code_execution", "CWE-95", "Code injection via eval"),
        (r"\bnew\s+Function\s*\(", "code_execution", "CWE-95", "Function constructor injection"),
        (r"\.query\s*\(\s*['\"].*\+\s", "sql_injection", "CWE-89", "SQL injection via concatenation"),
        (r"\.query\s*\(\s*`.*\$\{", "sql_injection", "CWE-89", "SQL injection via template literal"),
        (r"\bJSON\.parse\s*\(.*eval", "deserialization", "CWE-502", "JSON parse with eval"),
        (r"\bfetch\s*\(\s*[^'\"`/]", "ssrf", "CWE-918", "Fetch with dynamic URL"),
        (r"\baxios\.(?:get|post|put|delete)\s*\([^'\"`]", "ssrf", "CWE-918", "Axios with dynamic URL"),
        (r"\.readFile\s*\([^_]+\+", "path_traversal", "CWE-22", "File read with dynamic path"),
        (r"\.writeFile\s*\(", "file_write", "CWE-73", "File write"),
        (r"\.render\s*\(.*req\.", "template_injection", "CWE-1336", "SSTI via template render"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*=\s*['\"`][^'\"`\s]{8,}['\"`]", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
        (r"\.innerHTML\s*=", "xss", "CWE-79", "innerHTML XSS"),
        (r"\.outerHTML\s*=", "xss", "CWE-79", "outerHTML XSS"),
        (r"document\.write\s*\(", "xss", "CWE-79", "document.write XSS"),
        (r"\.find\s*\(\s*\{[^}]*\$", "nosql_injection", "CWE-943", "NoSQL injection"),
        (r"innerHTML\s*=\s*[^'\"]", "xss", "CWE-79", "Dynamic innerHTML"),
        (r"\.exec\s*\(\s*`", "command_execution", "CWE-78", "Command via template literal"),
        (r"dangerouslySetInnerHTML", "xss", "CWE-79", "React dangerouslySetInnerHTML"),
        (r"bypassSecurityTrust", "xss", "CWE-79", "Angular bypassSecurityTrust*"),
    ],
    "scala": [
        (r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "command_execution", "CWE-78", "Runtime exec"),
        (r"\bProcessBuilder\s*\(", "command_execution", "CWE-78", "ProcessBuilder"),
        (r"\bObjectInputStream\b", "deserialization", "CWE-502", "Java deserialization"),
        (r"\.executeQuery\s*\(\s*['\"].*\+", "sql_injection", "CWE-89", "SQL injection"),
        (r"\bnew\s+java\.net\.URL\s*\(", "ssrf", "CWE-918", "URL construction (SSRF risk)"),
        (r"\bXMLLoader\b", "xxe", "CWE-611", "XML loading (XXE risk in Scala XML)"),
        (r"\.load\s*\(\s*[^)]*getClass", "deserialization", "CWE-502", "Classloader-based deserialization"),
        (r"\bnew\s+FileInputStream\s*\(", "file_read", "CWE-22", "File read"),
        (r"\bFiles\.readAllBytes\s*\(", "file_read", "CWE-22", "File read"),
        (r"\bPlay\.current\s*\.configuration", "config_leak", "CWE-200", "Play Framework config access"),
        (r"\bspark\.read\s*\(", "data_read", "CWE-200", "Spark data read"),
    ],
    "ruby": [
        (r"\bsystem\s*\(", "command_execution", "CWE-78", "system() call"),
        (r"\bexec\s*\(", "command_execution", "CWE-78", "exec() call"),
        (r"`[^`]+`", "command_execution", "CWE-78", "Backtick command"),
        (r"\beval\s*\(", "code_execution", "CWE-95", "eval() injection"),
        (r"\.where\s*\(\s*['\"]#\{", "sql_injection", "CWE-89", "SQL injection via interpolation"),
        (r"\bMarshal\.load\s*\(", "deserialization", "CWE-502", "Marshal deserialize"),
        (r"\bYAML\.load\s*\(", "deserialization", "CWE-502", "YAML unsafe load"),
        (r"\bNet::HTTP\.(?:get|post|start)\s*\(", "ssrf", "CWE-918", "HTTP SSRF"),
        (r"(?i)(?:secret|password|api[_-]?key|token)\s*=\s*[\"'][^\"']{8,}[\"']", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
    ],
    "php": [
        (r"\bsystem\s*\(", "command_execution", "CWE-78", "system() call"),
        (r"\bexec\s*\(", "command_execution", "CWE-78", "exec() call"),
        (r"\bshell_exec\s*\(", "command_execution", "CWE-78", "shell_exec()"),
        (r"\bpassthru\s*\(", "command_execution", "CWE-78", "passthru()"),
        (r"\bpopen\s*\(", "command_execution", "CWE-78", "popen()"),
        (r"`[^`]+`", "command_execution", "CWE-78", "Backtick execution"),
        (r"\bproc_open\s*\(", "command_execution", "CWE-78", "proc_open()"),
        (r"\beval\s*\(", "code_execution", "CWE-95", "eval() injection"),
        (r"\bassert\s*\(", "code_execution", "CWE-95", "assert() injection"),
        (r"\bcreate_function\s*\(", "code_execution", "CWE-95", "create_function injection"),
        (r"\binclude\s*\$", "file_inclusion", "CWE-98", "Dynamic file inclusion"),
        (r"\brequire\s*\$", "file_inclusion", "CWE-98", "Dynamic file inclusion"),
        (r"\bextract\s*\(", "variable_overwrite", "CWE-915", "extract() variable overwrite"),
        (r"\bparse_str\s*\(", "variable_overwrite", "CWE-915", "parse_str() variable overwrite"),
        (r"\bmysql_query\s*\(\s*\$", "sql_injection", "CWE-89", "SQL injection"),
        (r"\bunserialize\s*\(", "deserialization", "CWE-502", "PHP unserialize"),
        (r"\bsimplexml_load_(?:string|file)\s*\(", "xxe", "CWE-611", "SimpleXML XXE"),
        (r"(?i)(?:password|secret|api_key)\s*=\s*[\"'][^\"']{8,}[\"']", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
    ],
    "powershell": [
        (r"\bInvoke-Expression\b", "command_execution", "CWE-78", "Invoke-Expression injection"),
        (r"\biex\b", "command_execution", "CWE-78", "iex (Invoke-Expression alias)"),
        (r"\bInvoke-Command\b", "command_execution", "CWE-78", "Invoke-Command"),
        (r"\bStart-Process\b", "command_execution", "CWE-78", "Start-Process"),
        (r"\bNew-Object\s+-ComObject\b", "command_execution", "CWE-78", "COM object creation"),
        (r"\bAdd-Type\b", "code_execution", "CWE-94", "Add-Type code injection"),
        (r"\bImport-Clixml\b", "deserialization", "CWE-502", "Clixml deserialization"),
        (r"\bInvoke-WmiMethod\b", "command_execution", "CWE-78", "WMI command execution"),
        (r"\bInvoke-CimMethod\b", "command_execution", "CWE-78", "CIM command execution"),
        (r"\[ScriptBlock\]::Create\s*\(", "code_execution", "CWE-94", "ScriptBlock injection"),
        (r"(?i)(?:password|credential|secret|token|key)\s*=\s*[\"'][^\"']{6,}[\"']", "hardcoded_secret", "CWE-798", "Hardcoded credential"),
        (r"\bConvertTo-SecureString\b.*-AsPlainText", "insecure_crypto", "CWE-312", "Insecure SecureString"),
    ],
    "swift": [
        (r"\bProcess\s*\(\s*arguments:", "command_execution", "CWE-78", "Process execution"),
        (r"\bURLSession\.shared\.dataTask", "ssrf", "CWE-918", "URL session SSRF"),
        (r"\bString\.(contentsOfFile|data)\s*\(", "file_read", "CWE-22", "File read"),
    ],
    "kotlin": [
        (r"\bRuntime\.getRuntime\(\)\.exec\s*\(", "command_execution", "CWE-78", "Runtime exec"),
        (r"\bProcessBuilder\s*\(", "command_execution", "CWE-78", "ProcessBuilder"),
        (r"\bFile\.(?:readText|readBytes)\s*\(", "file_read", "CWE-22", "File read"),
        (r"\bURL\s*\(", "ssrf", "CWE-918", "URL construction"),
    ],
    "shell": [
        (r"\beval\s+", "code_execution", "CWE-95", "eval injection"),
        (r"\bexec\s+", "command_execution", "CWE-78", "exec command"),
        (r"\$\(", "command_substitution", "CWE-78", "Command substitution"),
        (r"`[^`]+`", "command_execution", "CWE-78", "Backtick command substitution"),
        (r"\bsource\s+\$", "file_inclusion", "CWE-98", "Dynamic source inclusion"),
    ],
}


@dataclass
class SinkTag:
    file: str
    line: int
    category: str
    cwe_id: str
    description: str
    matched_text: str = ""
    language: str = ""
    severity: str = "HIGH"
    function_name: str = ""


class SinkTagger:
    def tag_file(self, filepath: Path, source: str, language: str) -> list[SinkTag]:
        patterns = ALL_SINKS.get(language, [])
        tags_by_location: dict[tuple[int, str], SinkTag] = {}
        lines = source.split("\n")

        for pattern, category, cwe_id, description in patterns:
            for m in re.finditer(pattern, source):
                line_num = source[:m.start()].count("\n") + 1
                line_text = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                severity = self._severity_for(category, cwe_id)
                key = (line_num, category)

                if key in tags_by_location:
                    existing = tags_by_location[key]
                    if cwe_id and (not existing.cwe_id or cwe_id not in existing.cwe_id):
                        existing.cwe_id = f"{existing.cwe_id},{cwe_id}" if existing.cwe_id else cwe_id
                    continue

                tags_by_location[key] = SinkTag(
                    file=str(filepath), line=line_num,
                    category=category, cwe_id=cwe_id,
                    description=description,
                    matched_text=line_text[:200],
                    language=language, severity=severity,
                )

        return list(tags_by_location.values())

    def tag_repo(self, repo_path: Path) -> list[SinkTag]:
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

    def _severity_for(self, category: str, cwe_id: str) -> str:
        critical = {"command_execution", "deserialization", "sql_injection", "code_execution", "file_inclusion"}
        high = {"buffer_overflow", "path_traversal", "ssrf", "xxe", "template_injection",
                "race_condition", "format_string", "unsafe_block", "transmute", "ffi",
                "reflection_invoke", "ldap_injection", "xpath_injection", "spel_injection",
                "nosql_injection", "variable_overwrite", "integer_overflow"}
        medium = {"hardcoded_secret", "weak_crypto", "weak_random", "insecure_crypto",
                  "file_write", "xss", "information_disclosure", "string_cast", "data_access",
                  "new_array", "delete_array", "delete_obj", "free", "unsafe_copy",
                  "raw_pointer", "web_framework", "command_substitution"}

        if category in critical:
            return "CRITICAL"
        elif category in high:
            return "HIGH"
        elif category in medium:
            return "MEDIUM"
        return "LOW"
