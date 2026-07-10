"""Step 1: Target classification — maps ANY repository to correct vulnerability research category.

Covers: kernel, native, web, CLI, PowerShell, embedded, AI/ML, compiler, browser, container, distributed, etc.
Default: general_application (not web_app — won't apply wrong methodology).
"""
from __future__ import annotations

from typing import Any

from src.utils.logger import get_logger

logger = get_logger()

CLASSIFICATION_TABLE = [
    # Order matters — first match wins
    {
        "name": "Kernel / Driver",
        "primary": "kernel",
        "signals": {
            "dirs_contain": ["arch", "kernel", "drivers", "fs", "net", "mm", "include/linux"],
            "build_files": ["Kconfig", "Kbuild", "Makefile"],
            "files_contain": ["MODULE_LICENSE", "GPL", "module_init", "module_exit"],
        },
        "refs": ["kernel.md", "native-memory.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "Browser / Sandbox",
        "primary": "browser_sandbox",
        "signals": {
            "dirs_contain": ["content", "blink", "mojo", "v8", "third_party/blink"],
            "build_files": ["DEPS", "BUILD.gn", ".gn"],
            "files_contain": ["renderer_host", "BrowserMain", "RenderProcessHost", "sandbox::"],
        },
        "refs": ["browser.md", "sandbox-boundaries.md", "native-memory.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "PowerShell / Windows Automation",
        "primary": "powershell",
        "signals": {
            "extensions_contain": [".ps1", ".psm1", ".psd1"],
            "files_contain": ["Cmdlet", "PSCmdlet", "System.Management.Automation"],
            "dirs_contain": ["src/System.Management.Automation", "Modules", "PowerShell"],
            "build_files": ["PowerShell.sln", ".csproj"],
            "_dual_language": "C#",
        },
        "refs": ["cli-tools.md", "dotnet.md", "powershell.md", "serialization.md", "generic-sinks.md", "exploit-patterns.md", "supply-chain.md"],
    },
    {
        "name": "AI / ML Framework",
        "primary": "ai_framework",
        "signals": {
            "dirs_contain": ["tensorflow", "pytorch", "transformers", "onnx", "openvino"],
            "files_contain": ["tensorflow", "torch.nn", "keras", "model.fit", "saved_model"],
            "build_files": ["setup.py", "pyproject.toml", "Cargo.toml", "CMakeLists.txt"],
        },
        "refs": ["web-app.md", "serialization.md", "native-memory.md", "generic-sinks.md", "exploit-patterns.md", "supply-chain.md"],
    },
    {
        "name": "Compiler / Language Toolchain",
        "primary": "compiler",
        "signals": {
            "dirs_contain": ["parser", "lexer", "ast", "codegen", "ir", "semantic"],
            "files_contain": ["tokenizer", "parser::", "codegen", "llvm", "tokens"],
            "build_files": ["CMakeLists.txt", "Cargo.toml"],
        },
        "refs": ["parsers.md", "native-memory.md", "cli-tools.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "Embedded / IoT / RTOS",
        "primary": "embedded",
        "signals": {
            "dirs_contain": ["board", "arch", "hal", "bsp", "drivers", "target"],
            "build_files": ["CMakeLists.txt", "Makefile", "platformio.ini"],
            "files_contain": ["ISR(", "__attribute__((interrupt", "HAL_", "BSP_", "FreeRTOS", "Zephyr"],
        },
        "refs": ["native-memory.md", "kernel.md", "parsers.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "Native C/C++ Library",
        "primary": "native_memory",
        "signals": {
            "primary_language_in": ["C", "C++"],
            "dirs_contain": ["src", "lib", "include"],
            "build_files": ["CMakeLists.txt", "Makefile", "meson.build"],
        },
        "refs": ["native-memory.md", "parsers.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "Distributed System",
        "primary": "distributed",
        "signals": {
            "dirs_contain": ["services", "microservices", "proto", "api", "rpc"],
            "build_files": ["docker-compose.yml", "docker-compose.yaml", "Dockerfile"],
            "architecture": "microservices",
        },
        "refs": ["distributed-systems.md", "web-app.md", "serialization.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "Container Runtime",
        "primary": "container",
        "signals": {
            "dirs_contain": ["container", "runtime", "oci", "cgroup", "namespace"],
            "files_contain": ["container", "containerd", "runc", "Specgen", "mount_ns"],
            "build_files": ["Dockerfile"],
        },
        "refs": ["container-runtime.md", "kernel.md", "native-memory.md", "sandbox-boundaries.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "CLI Tool / Dev Tooling",
        "primary": "cli_tool",
        "signals": {
            "architecture_in": ["script_or_cli", "cli"],
            "build_files": ["setup.py", "Cargo.toml", "go.mod", "package.json", "Makefile"],
        },
        "refs": ["cli-tools.md", "generic-sinks.md", "exploit-patterns.md", "supply-chain.md"],
    },
    {
        "name": "Java Platform",
        "primary": "java_platform",
        "signals": {
            "primary_language": "Java",
        },
        "refs": ["java-platform.md", "serialization.md", "web-app.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": ".NET Platform",
        "primary": "dotnet",
        "signals": {
            "primary_language": "C#",
        },
        "refs": ["dotnet.md", "serialization.md", "web-app.md", "generic-sinks.md", "exploit-patterns.md"],
    },
    {
        "name": "Web Application / API Backend",
        "primary": "web_app",
        "signals": {
            "frameworks_contains_any": ["spring", "django", "fastapi", "flask", "express", "next", "react", "vue", "angular", "rails", "laravel", "nest"],
        },
        "refs": ["web-app.md", "generic-sinks.md", "exploit-patterns.md"],
    },
]

DEFAULT_CLASSIFICATION = {
    "name": "General Application",
    "primary": "general_application",
    "refs": ["generic-sinks.md", "exploit-patterns.md"],
}


def run(fingerprint: dict[str, Any]) -> dict[str, Any]:
    logger.info("Step 1: Classifying target...")

    for rule in CLASSIFICATION_TABLE:
        if _match_rule(fingerprint, rule["signals"]):
            result = _build_result(fingerprint, rule)
            logger.info(f"  Class: {result['primary_class']} ({result['display_name']})")
            logger.info(f"  Refs: {', '.join(result['loaded_refs'])}")
            return result

    result = _build_result(fingerprint, DEFAULT_CLASSIFICATION)
    logger.info(f"  Class: {result['primary_class']} ({result['display_name']}) (default)")
    return result


def _match_rule(fp: dict[str, Any], signals: dict[str, Any]) -> bool:
    if "dirs_contain" in signals:
        if not _repo_dirs_match(fp.get("repo_path", ""), signals["dirs_contain"]):
            return False

    if "build_files" in signals:
        bf = set(fp.get("build_systems", []))
        build_signals = signals["build_files"]
        # Check if any build file exists (not system name, actual filename)
        # We check build_systems from fingerprint + raw file check
        found = False
        for b in build_signals:
            if b in bf:
                found = True
                break
            # Also check if the file literally exists (for Kconfig, Kbuild, etc)
            if not found:
                for f in _list_files(fp.get("repo_path", ""), 200):
                    if f.endswith(b) or b in f:
                        found = True
                        break
        if not found:
            return False

    if "files_contain" in signals:
        if not _files_contain(fp.get("repo_path", ""), signals["files_contain"]):
            return False

    if "primary_language" in signals:
        if fp.get("primary_language") != signals["primary_language"]:
            return False

    if "primary_language_in" in signals:
        if fp.get("primary_language") not in signals["primary_language_in"]:
            return False

    if "_dual_language" in signals:
        if fp.get("primary_language") != signals["_dual_language"]:
            return False

    if "extensions_contain" in signals:
        langs = fp.get("languages", {})
        exts_present = set()
        for lang in langs:
            for ext_info in signals["extensions_contain"]:
                if ext_info in str(lang).lower() or ext_info in str(langs).lower():
                    exts_present.add(ext_info)
        if len(exts_present) < len(signals["extensions_contain"]) * 0.5:
            return False

    if "architecture" in signals:
        if fp.get("architecture") != signals["architecture"]:
            return False

    if "architecture_in" in signals:
        if fp.get("architecture") not in signals["architecture_in"]:
            return False

    if "frameworks_contains_any" in signals:
        fws = [f.lower() for f in fp.get("frameworks", [])]
        if not any(s in " ".join(fws) for s in signals["frameworks_contains_any"]):
            return False

    return True


def _repo_dirs_match(repo_path: str, dirs: list[str]) -> bool:
    from pathlib import Path
    p = Path(repo_path)
    repo_dirs = set()
    try:
        for item in list(p.iterdir())[:100]:
            if item.is_dir():
                repo_dirs.add(item.name.lower())
    except Exception:
        pass
    for d in dirs:
        if "/" in d or "\\" in d:
            full_path = p / d
            if full_path.exists() and full_path.is_dir():
                return True
        elif d.lower() in repo_dirs:
            return True
    return False


def _files_contain(repo_path: str, keywords: list[str]) -> bool:
    from pathlib import Path
    p = Path(repo_path)
    for kw in keywords:
        found = False
        for ext in ["*.c", "*.h", "*.cpp", "*.hpp", "*.cs", "*.py", "*.rs", "*.java", "*.ps1", "*.psm1"]:
            for f in p.rglob(ext):
                if found:
                    break
                try:
                    content = f.read_text(errors="replace")[:4096]
                    if kw in content:
                        found = True
                        break
                except Exception:
                    continue
        if not found:
            return False
    return True


def _list_files(repo_path: str, limit: int) -> list[str]:
    from pathlib import Path
    p = Path(repo_path)
    files = []
    try:
        for f in p.iterdir():
            files.append(f.name)
            if len(files) >= limit:
                break
    except Exception:
        pass
    return files


def _build_result(fp: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    refs = list(rule["refs"])

    if fp.get("build_systems") and "supply-chain.md" not in refs:
        refs.append("supply-chain.md")

    if fp.get("ecosystems") and "supply-chain.md" not in refs:
        refs.append("supply-chain.md")

    primary = rule["primary"]
    secondary = []

    if primary != "web_app":
        fw_text = str(fp.get("frameworks", [])).lower()
        web_fws = ["express", "fastapi", "flask", "django", "rails", "spring"]
        matched_web = [fw for fw in web_fws if fw in fw_text]
        if len(matched_web) >= 2:
            secondary.append("web_app")

    return {
        "primary_class": primary,
        "secondary_classes": secondary,
        "display_name": rule["name"],
        "loaded_refs": refs,
        "rationale": f"Matched: {rule['name']}",
        "key_signals": {
            "language": fp.get("primary_language"),
            "architecture": fp.get("architecture"),
            "frameworks": fp.get("frameworks"),
        },
    }
