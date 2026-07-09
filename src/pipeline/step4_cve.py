"""Step 4: Build CVE exploit pattern catalog — the LLM's hunting guide.

Queries the unified CVE database and builds a structured catalog of known exploit patterns.
Organized by: exploit class, target type, attack surface, CWE.
LLM uses this to HUNT for analogous patterns in the target codebase — not just trace pre-found sinks.
"""
from __future__ import annotations

from typing import Any

from src.knowledge.cve_db import CVEDatabase
from src.utils.logger import get_logger

logger = get_logger()

EXPLOIT_CLASSES = {
    "memory_safety": ["CWE-119", "CWE-120", "CWE-122", "CWE-125", "CWE-416", "CWE-415",
                       "CWE-476", "CWE-787", "CWE-788", "CWE-190", "CWE-191", "CWE-680",
                       "CWE-131", "CWE-823", "CWE-824", "CWE-908", "CWE-843"],
    "command_injection": ["CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-917"],
    "sql_injection": ["CWE-89", "CWE-564", "CWE-943"],
    "deserialization": ["CWE-502", "CWE-913"],
    "ssrf": ["CWE-918", "CWE-441"],
    "auth_bypass": ["CWE-287", "CWE-288", "CWE-289", "CWE-290", "CWE-306",
                     "CWE-307", "CWE-384", "CWE-613", "CWE-639", "CWE-640",
                     "CWE-862", "CWE-863"],
    "path_traversal": ["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
    "xxe": ["CWE-611", "CWE-776", "CWE-827"],
    "race_condition": ["CWE-362", "CWE-367", "CWE-366", "CWE-368", "CWE-822"],
    "crypto": ["CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-338", "CWE-347",
               "CWE-798", "CWE-916", "CWE-312", "CWE-319", "CWE-311"],
    "info_leak": ["CWE-200", "CWE-201", "CWE-209", "CWE-532", "CWE-538", "CWE-540"],
    "privilege_escalation": ["CWE-250", "CWE-264", "CWE-266", "CWE-269", "CWE-271",
                              "CWE-272", "CWE-274", "CWE-276"],
    "xss": ["CWE-79", "CWE-80", "CWE-81", "CWE-82", "CWE-83"],
    "csrf": ["CWE-352"],
    "open_redirect": ["CWE-601"],
    "prototype_pollution": ["CWE-1321", "CWE-915"],
    "format_string": ["CWE-134"],
    "integer_overflow": ["CWE-190", "CWE-191", "CWE-680"],
}

ATTACK_SURFACES = {
    "http_endpoint": ["http", "rest", "api", "endpoint", "controller", "handler", "route",
                       "web", "graphql", "grpc", "websocket", "socket.io"],
    "cli_interface": ["cli", "command", "argument", "arg", "argv", "flag", "option",
                       "console", "terminal", "shell", "parameter"],
    "file_parsing": ["parse", "parser", "xml", "json", "yaml", "csv", "pdf", "image",
                      "media", "codec", "protobuf", "serialize", "deserialize", "load",
                      "import", "read", "format", "decode", "encode"],
    "ipc_interface": ["ipc", "pipe", "socket", "message", "rpc", "channel", "mojo",
                       "com", "dcom", "dbus", "netlink", "broker", "bus", "shared memory"],
    "plugin_api": ["plugin", "extension", "addon", "module", "hook", "callback",
                    "script", "lua", "python", "javascript", "v8", "embed"],
    "kernel_boundary": ["syscall", "ioctl", "driver", "proc", "sysfs", "debugfs",
                         "copy_from_user", "copy_to_user", "netlink", "bpf", "ebpf"],
    "file_system": ["file", "path", "directory", "folder", "symlink", "link", "archive",
                     "zip", "tar", "extract", "upload", "download", "temp", "tmp"],
    "network": ["network", "socket", "tcp", "udp", "http", "dns", "tls", "ssl",
                 "packet", "protocol", "request", "response", "proxy"],
    "process": ["process", "exec", "spawn", "fork", "createprocess", "thread",
                 "signal", "interrupt", "handler", "daemon"],
}

TARGET_TYPE_MAPPING = {
    "kernel": ["kernel", "linux kernel", "windows kernel", "driver", "kvm", "xen", "hypervisor"],
    "browser_sandbox": ["browser", "chrome", "chromium", "firefox", "safari", "webkit",
                         "blink", "v8", "spidermonkey", "renderer", "sandbox", "electron"],
    "powershell": ["powershell", "ps", "cmdlet", "pscmdlet", "automation"],
    "ide_editor": ["vscode", "visual studio code", "monaco", "editor", "ide", "intellij",
                    "eclipse", "atom", "sublime", "notepad++", "vim", "neovim", "emacs"],
    "compiler": ["compiler", "gcc", "clang", "llvm", "rustc", "javac", "typescript",
                  "toolchain", "codegen", "jit", "aot", "transpiler"],
    "database": ["database", "sql", "postgres", "mysql", "mongodb", "redis", "sqlite",
                  "oracle", "mariadb", "cassandra", "elasticsearch"],
    "ai_ml": ["tensorflow", "pytorch", "onnx", "keras", "transformers", "model",
              "neural", "training", "inference", "tflite", "openvino"],
    "container": ["container", "docker", "containerd", "runc", "podman", "kubernetes",
                   "k8s", "namespace", "cgroup", "oci"],
    "web_server": ["nginx", "apache", "iis", "tomcat", "jetty", "caddy", "haproxy",
                    "envoy", "traefik", "proxy", "gateway", "load balancer"],
    "cli_tool": ["git", "npm", "pip", "cargo", "yarn", "curl", "wget", "ffmpeg",
                  "imagemagick", "openssl", "openssh", "bash", "zsh", "make"],
    "native_library": ["library", "lib", "sdk", "framework", "dll", "so", "dylib",
                        "ffi", "jni", "cgo", "pinvoke", "binding"],
    "protocol": ["protocol", "tls", "ssl", "ssh", "smtp", "ftp", "rdp", "smb",
                  "dns", "dhcp", "ntp", "snmp", "bgp", "ospf", "quic", "http2", "http3"],
}


def run(
    fingerprint: dict[str, Any],
    classification: dict[str, Any],
    static_analysis: dict[str, Any],
) -> dict[str, Any]:
    logger.info("Step 4: Building CVE exploit pattern catalog...")

    primary = classification.get("primary_class", "general_application")
    primary_lang = fingerprint.get("primary_language", "")
    frameworks = fingerprint.get("frameworks", [])

    db = CVEDatabase()

    catalog: dict[str, list[dict[str, Any]]] = {k: [] for k in EXPLOIT_CLASSES}
    target_hits: list[dict[str, Any]] = []
    all_kev: list[dict[str, Any]] = []

    target_type_keywords = _get_target_keywords(primary, primary_lang, frameworks)

    # Query: all KEV entries for this tech stack
    if target_type_keywords:
        kev_all = db.search(
            query=" ".join(target_type_keywords[:5]),
            kev_only=True, limit=100,
        )
        all_kev = _format_cves(kev_all)

    # Query: per exploit class
    for exploit_class, cwe_ids in EXPLOIT_CLASSES.items():
        results = db.search(
            query=" ".join(target_type_keywords[:5]),
            cwe_ids=cwe_ids,
            limit=15,
            min_epss=0.01,
        )
        if results:
            catalog[exploit_class] = _format_cves(results)

    # Query: related technologies (not just exact match — what similar targets had)
    related_keywords = _get_related_keywords(primary)
    for exploit_class, cwe_ids in EXPLOIT_CLASSES.items():
        if len(catalog[exploit_class]) < 5 and related_keywords:
            results = db.search(
                query=" ".join(related_keywords[:3]),
                cwe_ids=cwe_ids,
                limit=5,
                kev_only=True,
            )
            if results:
                catalog[exploit_class].extend(_format_cves(results)[:3])

    # All target-specific hits (unclassified by exploit type)
    if target_type_keywords:
        broad = db.search(
            query=" ".join(target_type_keywords[:5]),
            limit=30,
            min_epss=0.02,
        )
        target_hits = _format_cves(broad)

    db.close()

    # Build the catalog summary for the LLM
    catalog_text = _build_catalog_text(catalog, all_kev, target_hits, primary, frameworks)

    total_cves = sum(len(v) for v in catalog.values()) + len(target_hits)
    kev_count = len(all_kev)
    classes_with_hits = sum(1 for v in catalog.values() if v)

    logger.info(f"  Catalog: {total_cves} CVEs across {classes_with_hits} exploit classes ({kev_count} KEV)")

    return {
        "catalog": catalog,
        "catalog_text": catalog_text,
        "all_kev": all_kev,
        "target_hits": target_hits,
        "exploit_classes_covered": classes_with_hits,
        "total_cves_found": total_cves,
        "kev_count": kev_count,
        "target_type_keywords": target_type_keywords,
        "attack_surface_hints": _get_attack_surface_hints(primary, static_analysis),
    }


def _format_cves(rows: list[dict]) -> list[dict[str, Any]]:
    return [
        {
            "cve_id": r.get("cve_id") or r.get("id", ""),
            "description": (r.get("description") or "")[:300],
            "cvss_score": r.get("cvss_score"),
            "epss_score": r.get("epss_score"),
            "kev_member": r.get("kev_member"),
            "cwe_ids": r.get("cwe_ids"),
            "severity": r.get("severity"),
        }
        for r in rows
    ]


def _get_target_keywords(primary: str, language: str, frameworks: list[str]) -> list[str]:
    keywords = []
    keywords.append(language)

    for fw in frameworks:
        keywords.append(fw)

    mapping = TARGET_TYPE_MAPPING.get(primary, [])
    keywords.extend(mapping[:3])

    return list(set(keywords))[:8]


def _get_related_keywords(primary: str) -> list[str]:
    related = {
        "kernel": ["driver", "operating system", "privilege escalation"],
        "powershell": ["automation", "scripting", "shell"],
        "ide_editor": ["code editor", "editor plugin", "file parsing"],
        "compiler": ["parser", "code generation", "jit"],
        "ai_ml": ["machine learning", "neural network", "model loading"],
        "dotnet": ["deserialization", "remote code execution", "aspnet"],
        "web_app": ["injection", "authentication bypass", "csrf"],
        "cli_tool": ["command injection", "argument parsing", "file handling"],
        "native_memory": ["buffer overflow", "use after free", "memory corruption"],
        "container": ["escape", "privilege escalation", "namespace"],
    }
    return related.get(primary, [])


def _build_catalog_text(
    catalog: dict[str, list[dict]],
    all_kev: list[dict],
    target_hits: list[dict],
    primary: str,
    frameworks: list[str],
) -> str:
    lines = [
        f"=== CVE EXPLOIT PATTERN CATALOG ===",
        f"Target type: {primary}",
        f"Frameworks: {', '.join(frameworks) if frameworks else 'none detected'}",
        f"",
    ]

    if all_kev:
        lines.append(f"### CRITICAL: {len(all_kev)} CISA KEV — actively exploited in the wild")
        for cve in all_kev[:10]:
            lines.append(f"  {cve['cve_id']}: {cve['description'][:200]}")
            lines.append(f"    CVSS: {cve.get('cvss_score')}, EPSS: {cve.get('epss_score')}, CWE: {cve.get('cwe_ids')}")
        lines.append("")

    classes_with_data = [(k, v) for k, v in catalog.items() if v]
    for exploit_class, cves in classes_with_data:
        kev_subset = [c for c in cves if c.get("kev_member")]
        label = f"### {exploit_class.replace('_', ' ').title()}"
        if kev_subset:
            label += f" ({len(kev_subset)} actively exploited!)"
        lines.append(label)

        search_guide = _get_search_guidance(exploit_class, primary)
        if search_guide:
            lines.append(f"  HUNT FOR: {search_guide}")

        for cve in cves[:5]:
            kev_mark = " [KEV — ACTIVE EXPLOIT]" if cve.get("kev_member") else ""
            lines.append(f"  {cve['cve_id']}: {cve['description'][:200]}{kev_mark}")
        lines.append("")

    if target_hits:
        lines.append(f"### Other CVEs for this technology stack ({len(target_hits)})")
        for cve in target_hits[:15]:
            kev_mark = " [KEV]" if cve.get("kev_member") else ""
            lines.append(f"  {cve['cve_id']}: {cve['description'][:150]}{kev_mark}")
        lines.append("")

    lines.append("### YOUR TASK")
    lines.append("Use this catalog as a HUNTING GUIDE. For each exploit class:")
    lines.append("1. Search the codebase for analogous vulnerable patterns")
    lines.append("2. Look at entry points that match the attack surface described")
    lines.append("3. Trace whether input reaches dangerous operations without proper validation")
    lines.append("4. Generate HIGH-confidence exploit hypotheses with exact file:line references")
    lines.append("5. PRIORITIZE finding analogs of KEV-listed CVEs — these are what attackers actually exploit")

    return "\n".join(lines)


def _get_search_guidance(exploit_class: str, primary: str) -> str:
    guidance = {
        "memory_safety": "Audit all memory operations: allocations, frees, array access, pointer arithmetic, type casts. Look for missing bounds checks, use-after-free, double free, integer overflow in size calculations.",
        "command_injection": "Track how external input reaches command/shell execution. Check for string concatenation building commands, missing escaping, shell metacharacters.",
        "deserialization": "Find all deserialization points. Check what types can be instantiated, whether type validation exists, if gadget chains are possible.",
        "ssrf": "Find all HTTP client calls with dynamic URLs. Check URL validation, protocol allowlisting, DNS rebinding protection.",
        "auth_bypass": "Audit authentication middleware, session management, JWT validation, OAuth flows. Look for missing checks, logic errors, path normalization bypasses.",
        "path_traversal": "Find all file path construction with user input. Check for canonicalization, symlink handling, archive extraction safety.",
        "race_condition": "Find shared mutable state with concurrent access. Check locking, TOCTOU in file ops, atomicity of multi-step operations.",
        "privilege_escalation": "Audit permission checks, role assignments, capability verification. Look for insufficient checks, confused deputy patterns.",
    }
    return guidance.get(exploit_class, "Search for similar patterns to the CVE descriptions above.")


def _get_attack_surface_hints(primary: str, static_analysis: dict) -> list[str]:
    hints = []
    surfaces = {
        "kernel": ["syscall handlers", "ioctl dispatch", "procfs/sysfs write handlers", "driver interfaces"],
        "powershell": ["cmdlet parameters", "script input ($args, Read-Host)", "COM interop", "Add-Script calls", "Invoke-Expression usage"],
        "dotnet": ["HTTP endpoints (controllers)", "deserialization points", "PowerShell host integration", "remoting endpoints"],
        "ide_editor": ["extension API", "IPC between processes", "file parsing (language server)", "workspace trust boundaries", "plugin loading"],
        "compiler": ["input file parsing", "intermediate representation", "optimization passes", "code generation output"],
        "ai_ml": ["model file loading", "graph/session inputs", "serialization (saved_model, onnx, pickle)", "ffi/native op boundaries"],
        "web_app": ["HTTP endpoints", "file upload", "webhook callbacks", "database queries", "template rendering"],
        "cli_tool": ["CLI arguments", "environment variables", "config file parsing", "plugin/extension loading"],
        "native_memory": ["public API functions", "file format parsers", "network protocol handlers", "ffi boundaries"],
        "browser_sandbox": ["renderer IPC messages", "Mojo interfaces", "extension API", "parser (HTML/CSS/JS/media)"],
        "container": ["container API", "OCI spec handling", "namespace/cgroup management", "image extraction"],
        "distributed": ["service API", "RPC endpoints", "message queue consumers", "proxy/gateway routing"],
    }
    hints = surfaces.get(primary, ["all external-facing code paths"])
    return hints
