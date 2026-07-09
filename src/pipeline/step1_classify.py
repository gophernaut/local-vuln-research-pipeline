"""Step 1: Target classification — maps repo to vulnerability research categories.

Uses classifiers.md decision tree + optional LLM confirmation.
"""
from __future__ import annotations

from typing import Any

from src.utils.logger import get_logger

logger = get_logger()


CLASSIFICATION_RULES = [
    {
        "conditions": [],
        "primary": "web_app",
        "refs": ["web-app.md", "generic-sinks.md", "exploit-patterns.md"],
        "name": "Web Application / Enterprise Backend",
    },
    {
        "conditions": [("architecture", "eq", "kernel_module")],
        "primary": "kernel",
        "refs": ["kernel.md", "native-memory.md", "generic-sinks.md", "exploit-patterns.md"],
        "name": "Systems / Kernel",
    },
    {
        "conditions": [("primary_language", "in", ["C", "C++"]), ("architecture", "in", ["native_library"])],
        "primary": "native_memory",
        "refs": ["native-memory.md", "parsers.md", "generic-sinks.md", "exploit-patterns.md"],
        "name": "Native Memory-Safety",
    },
    {
        "conditions": [("architecture", "eq", "microservices")],
        "primary": "distributed",
        "refs": ["distributed-systems.md", "web-app.md", "generic-sinks.md", "exploit-patterns.md"],
        "name": "Distributed Systems",
    },
    {
        "conditions": [("architecture", "in", ["script_or_cli", "cli"])],
        "primary": "cli_tool",
        "refs": ["cli-tools.md", "generic-sinks.md", "exploit-patterns.md", "supply-chain.md"],
        "name": "CLI / Agent / Dev Tooling",
    },
    {
        "conditions": [("build_systems_contains", "Docker")],
        "primary": "container",
        "refs": ["container-runtime.md", "web-app.md", "generic-sinks.md", "exploit-patterns.md"],
        "name": "Containerized Application",
    },
    {
        "conditions": [("primary_language", "eq", "Java")],
        "primary": "java_platform",
        "refs": ["java-platform.md", "serialization.md", "web-app.md", "generic-sinks.md", "exploit-patterns.md"],
        "name": "Java Platform",
    },
    {
        "conditions": [("primary_language", "eq", "C#")],
        "primary": "dotnet",
        "refs": ["dotnet.md", "serialization.md", "web-app.md", "generic-sinks.md", "exploit-patterns.md"],
        "name": ".NET Platform",
    },
]

DEFAULT_CLASSIFICATION = {
    "primary": "web_app",
    "refs": ["web-app.md", "generic-sinks.md", "exploit-patterns.md"],
    "name": "Web Application / API Backend",
}


def run(fingerprint: dict[str, Any]) -> dict[str, Any]:
    logger.info("Step 1: Classifying target...")

    for rule in CLASSIFICATION_RULES:
        if _matches_rule(fingerprint, rule["conditions"]):
            result = _build_result(fingerprint, rule)
            logger.info(f"  Class: {result['primary_class']} ({result['display_name']})")
            logger.info(f"  Loaded refs: {', '.join(result['loaded_refs'])}")
            return result

    result = _build_result(fingerprint, DEFAULT_CLASSIFICATION)
    logger.info(f"  Class: {result['primary_class']} ({result['display_name']}) (default)")
    return result


def run_with_llm(fingerprint: dict[str, Any], llm_client) -> dict[str, Any]:
    result = run(fingerprint)

    try:
        from src.llm.prompts import class_confirm_system
        prompt = class_confirm_system(result["loaded_refs"])

        user = (
            f"Repository fingerprint:\n"
            f"  Primary language: {fingerprint.get('primary_language')}\n"
            f"  Languages detected: {fingerprint.get('languages')}\n"
            f"  Frameworks detected: {fingerprint.get('frameworks')}\n"
            f"  Build systems: {fingerprint.get('build_systems')}\n"
            f"  Architecture pattern: {fingerprint.get('architecture')}\n"
            f"  Total files: {fingerprint.get('total_files')}\n"
            f"  Total lines: {fingerprint.get('total_lines')}\n\n"
            f"Initial classification: {result['primary_class']} ({result['display_name']})\n"
            f"Secondary classes: {result.get('secondary_classes', [])}\n\n"
            f"Confirm or suggest a better classification."
        )

        llm_result = llm_client.chat_json(prompt, user, max_tokens=512)
        if llm_result:
            result["llm_confirmed"] = True
            result["primary_class"] = llm_result.get("primary_class", result["primary_class"])
            if "secondary_classes" in llm_result:
                result["secondary_classes"] = llm_result["secondary_classes"]
            logger.info(f"  LLM confirmed: {result['primary_class']}")
    except Exception as e:
        logger.warning(f"  LLM classification skipped: {e}")
        result["llm_confirmed"] = False

    return result


def _matches_rule(fingerprint: dict[str, Any], conditions: list[tuple]) -> bool:
    for key, op, value in conditions:
        if key == "build_systems_contains":
            systems = fingerprint.get("build_systems", [])
            if value not in systems:
                return False
        elif op == "eq":
            if fingerprint.get(key) != value:
                return False
        elif op == "in":
            if fingerprint.get(key) not in value:
                return False
        elif op == "contains":
            val = fingerprint.get(key, "")
            if isinstance(val, list):
                if value not in val:
                    return False
            elif value not in str(val):
                return False
    return True


def _build_result(fingerprint: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    refs = list(rule["refs"])

    if fingerprint.get("build_systems"):
        refs.append("supply-chain.md")
    if fingerprint.get("primary_language") in ("Java", "C#", "Python", "Ruby", "JavaScript", "TypeScript"):
        if "serialization.md" not in refs:
            refs.append("serialization.md")

    secondary = []
    if rule["primary"] != "web_app" and any(
        fw in str(fingerprint.get("frameworks", []))
        for fw in ["express", "fastapi", "flask", "django", "rails", "spring", "asp.net"]
    ):
        secondary.append("web_app")

    ecosystems = fingerprint.get("ecosystems", [])
    if "npm" in ecosystems or "PyPI" in ecosystems or "Maven" in ecosystems:
        if "supply-chain.md" not in refs:
            refs.append("supply-chain.md")

    return {
        "primary_class": rule["primary"],
        "secondary_classes": secondary,
        "display_name": rule["name"],
        "loaded_refs": refs,
        "rationale": f"Matched rule: {rule['primary']} via conditions check",
        "key_signals": {
            "language": fingerprint.get("primary_language"),
            "architecture": fingerprint.get("architecture"),
            "frameworks": fingerprint.get("frameworks"),
        },
    }
