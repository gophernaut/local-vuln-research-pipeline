"""Step 0: Repository fingerprinting + SBOM extraction.

Detects: languages, frameworks, build system, architecture pattern,
extracts dependency manifests (SBOM), computes file inventory with hashes.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from src.utils.file_utils import collect_files, file_hash, repo_checkpoint_key
from src.knowledge.sbom import SBOMParser
from src.utils.logger import get_logger

logger = get_logger()

LANGUAGE_MAP = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java", ".kt": "Kotlin", ".scala": "Scala",
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#", ".vb": "VB.NET",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".ps1": "PowerShell", ".psm1": "PowerShell",
}

BUILD_SIGNALS = {
    "pom.xml": "Maven",
    "build.gradle": "Gradle", "build.gradle.kts": "Gradle",
    "package.json": "npm/Yarn",
    "Cargo.toml": "Cargo",
    "go.mod": "Go Modules",
    "requirements.txt": "pip",
    "pyproject.toml": "pip/Poetry",
    "Pipfile": "Pipenv",
    "setup.py": "setuptools",
    "Gemfile": "Bundler",
    "Makefile": "Make",
    "CMakeLists.txt": "CMake",
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    ".csproj": "MSBuild",
    "build.sbt": "SBT",
}

FRAMEWORK_SIGNALS = {
    "spring": "Spring Boot (Java)",
    "django": "Django (Python)",
    "fastapi": "FastAPI (Python)",
    "flask": "Flask (Python)",
    "express": "Express.js (Node)",
    "next": "Next.js (React)",
    "react": "React (JavaScript)",
    "vue": "Vue.js",
    "angular": "Angular",
    "nestjs": "NestJS (Node)",
    "rails": "Ruby on Rails",
    "laravel": "Laravel (PHP)",
    "gin-gonic": "Gin (Go)",
    "fiber": "Fiber (Go)",
    "actix": "Actix (Rust)",
    "axum": "Axum (Rust)",
    "rocket": "Rocket (Rust)",
    "asp.net": "ASP.NET (C#)",
}

MANIFEST_EXTS = {
    ".json", ".xml", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    ".csproj", ".fsproj", ".vbproj", ".sln", ".props", ".targets",
}


def run(repo_path: Path) -> dict[str, Any]:
    logger.info("Step 0: Fingerprinting repository...")

    repo_path = repo_path.resolve()
    checkpoint_key = repo_checkpoint_key(repo_path)

    files = collect_files(repo_path)
    logger.info(f"  Found {len(files)} source files")

    languages = Counter()
    build_systems = set()
    frameworks = set()
    total_lines = 0

    for f in files:
        ext = f.suffix.lower()
        lang = LANGUAGE_MAP.get(ext, "")
        if lang:
            languages[lang] += 1

        name = f.name
        if name in BUILD_SIGNALS:
            build_systems.add(BUILD_SIGNALS[name])

        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                content = fh.read(8192)
                total_lines += content.count("\n")
        except Exception:
            continue

    _detect_frameworks(repo_path, frameworks)

    architecture = _infer_architecture(repo_path, languages)

    sbom_parser = SBOMParser()
    dependencies = sbom_parser.parse(repo_path)
    logger.info(f"  SBOM: {len(dependencies)} dependencies across {len(set(d['ecosystem'] for d in dependencies))} ecosystems")

    result = {
        "repo_path": str(repo_path),
        "checkpoint_key": checkpoint_key,
        "total_files": len(files),
        "total_lines": total_lines,
        "languages": dict(languages.most_common()),
        "primary_language": languages.most_common(1)[0][0] if languages else "unknown",
        "build_systems": sorted(build_systems),
        "frameworks": sorted(frameworks),
        "architecture": architecture,
        "dependencies": dependencies,
        "ecosystems": sorted(set(d["ecosystem"] for d in dependencies)),
    }

    logger.info(f"  Primary: {result['primary_language']} | {result['architecture']}")
    logger.info(f"  Frameworks: {', '.join(frameworks) if frameworks else 'none detected'}")

    return result


def _detect_frameworks(repo_path: Path, frameworks: set[str]):
    """Only scan manifest/config files for framework signals, skipping test dirs."""
    manifest_files = _find_manifest_files(repo_path)
    for f in manifest_files:
        try:
            content = f.read_text(errors="replace")[:16384].lower()
            for sig, framework in FRAMEWORK_SIGNALS.items():
                if sig in content and framework not in frameworks:
                    frameworks.add(framework)
        except Exception:
            continue


def _find_manifest_files(repo_path: Path) -> list[Path]:
    TEST_DIRS = {"test", "tests", "spec", "fixtures", "mocks", "__tests__", "benchmarks"}
    manifest = []
    for f in repo_path.rglob("*"):
        if f.is_file() and (f.name in BUILD_SIGNALS or f.suffix.lower() in MANIFEST_EXTS):
            parts = set(p.lower() for p in f.parts)
            if not parts.intersection(TEST_DIRS):
                manifest.append(f)
        if len(manifest) >= 200:
            break
    return manifest


def _infer_architecture(repo_path: Path, languages: Counter) -> str:
    dirs = {d.name.lower() for d in repo_path.iterdir() if d.is_dir()}

    if "kernel" in dirs or "drivers" in dirs:
        return "kernel_module"
    if "src" in dirs:
        src_path = repo_path / "src"
        src_dirs = {d.name.lower() for d in src_path.iterdir() if d.is_dir()}
        if "main" in src_dirs and "test" in src_dirs:
            return "standard_application"
    if "services" in dirs or "microservices" in dirs:
        return "microservices"
    if "cmd" in dirs and "internal" in dirs:
        return "go_application"
    if "lib" in dirs and languages.get("C", 0) + languages.get("C++", 0) > languages.total() * 0.5:
        return "native_library"
    if "app" in dirs:
        return "web_application"
    if "src" in dirs and "tests" in dirs:
        return "library_or_framework"
    if "cli" in dirs or languages.get("Python", 0) > languages.total() * 0.5:
        return "script_or_cli"

    return "generic_application"
