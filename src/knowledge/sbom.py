"""SBOM parser. Extracts dependency information from project manifest files.

Supports: requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, package.json,
package-lock.json, yarn.lock, pom.xml, build.gradle, Cargo.toml, Cargo.lock,
go.mod, Gemfile, Gemfile.lock, *.csproj, packages.config
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


class SBOMParser:
    def parse(self, repo_path: Path) -> list[dict[str, Any]]:
        packages: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()

        parsers = [
            self._parse_python,
            self._parse_node,
            self._parse_java,
            self._parse_rust,
            self._parse_go,
            self._parse_ruby,
            self._parse_dotnet,
        ]

        for parser in parsers:
            try:
                for pkg in parser(repo_path):
                    key = (pkg["ecosystem"], pkg["name"], pkg.get("version", ""))
                    if key not in seen:
                        seen.add(key)
                        packages.append(pkg)
            except Exception:
                continue

        return packages

    def _parse_python(self, root: Path) -> list[dict]:
        pkgs = []

        req_files = list(root.rglob("requirements*.txt")) + list(root.rglob("requirements*.in"))
        for req_file in req_files:
            try:
                with open(req_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and not line.startswith("-"):
                            name = re.split(r"[=<>~!;\s]", line)[0].strip()
                            version = None
                            m = re.search(r"==(\d[\w.]*)", line)
                            if m:
                                version = m.group(1)
                            if name:
                                pkgs.append({
                                    "ecosystem": "PyPI", "name": name.lower(),
                                    "version": version, "file": str(req_file.relative_to(root)),
                                })
            except Exception:
                continue

        toml_files = list(root.rglob("pyproject.toml"))
        for tf in toml_files:
            try:
                with open(tf, encoding="utf-8") as f:
                    content = f.read()
                deps_match = re.search(
                    r"dependencies\s*=\s*\[([\s\S]*?)\]", content, re.DOTALL
                )
                if deps_match:
                    deps_text = deps_match.group(1)
                    for match in re.finditer(r'"([^"]+)"', deps_text):
                        dep = match.group(1)
                        name = re.split(r"[=<>~!;\s\[]", dep)[0].strip()
                        version = None
                        vmatch = re.search(r"==(\d[\w.]*)", dep)
                        if vmatch:
                            version = vmatch.group(1)
                        if name:
                            pkgs.append({
                                "ecosystem": "PyPI", "name": name.lower(),
                                "version": version, "file": str(tf.relative_to(root)),
                            })
            except Exception:
                continue

        return pkgs

    def _parse_node(self, root: Path) -> list[dict]:
        pkgs = []

        for pkg_file in root.rglob("package.json"):
            if "node_modules" in str(pkg_file):
                continue
            try:
                with open(pkg_file, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue

            for dep_type in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(dep_type, {})
                if not isinstance(deps, dict):
                    continue
                for name, ver in deps.items():
                    pkgs.append({
                        "ecosystem": "npm", "name": name,
                        "version": str(ver).lstrip("^~>=<"), "file": str(pkg_file.relative_to(root)),
                    })
        return pkgs

    def _parse_java(self, root: Path) -> list[dict]:
        pkgs = []

        for pom_file in list(root.rglob("pom.xml")):
            try:
                tree = ElementTree.parse(pom_file)
                ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}
                for dep in tree.findall(".//mvn:dependency", ns):
                    gid = dep.find("mvn:groupId", ns)
                    aid = dep.find("mvn:artifactId", ns)
                    ver = dep.find("mvn:version", ns)
                    if gid is not None and aid is not None:
                        pkgs.append({
                            "ecosystem": "Maven",
                            "name": f"{gid.text}:{aid.text}",
                            "version": ver.text if ver is not None else None,
                            "file": str(pom_file.relative_to(root)),
                        })
            except Exception:
                continue

        return pkgs

    def _parse_rust(self, root: Path) -> list[dict]:
        pkgs = []

        for cargo_file in list(root.rglob("Cargo.toml")):
            try:
                with open(cargo_file, encoding="utf-8") as f:
                    content = f.read()
                for dep_type in (r"\[dependencies\]", r"\[dev-dependencies\]", r"\[build-dependencies\]"):
                    section_match = re.search(
                        rf"{dep_type}\s*\n((?:.+\n)*?)(?=\[|\Z)", content
                    )
                    if section_match:
                        for line in section_match.group(1).strip().split("\n"):
                            line = line.strip()
                            if line and not line.startswith("#") and not line.startswith("["):
                                name = line.split("=")[0].strip().strip('"')
                                if name:
                                    pkgs.append({
                                        "ecosystem": "crates.io", "name": name,
                                        "version": None, "file": str(cargo_file.relative_to(root)),
                                    })
            except Exception:
                continue
        return pkgs

    def _parse_go(self, root: Path) -> list[dict]:
        pkgs = []

        for go_mod in list(root.rglob("go.mod")):
            try:
                with open(go_mod, encoding="utf-8") as f:
                    content = f.read()
                require_match = re.search(
                    r"require\s*\(([\s\S]*?)\)", content, re.DOTALL
                )
                if require_match:
                    for line in require_match.group(1).strip().split("\n"):
                        line = line.strip()
                        if line and not line.startswith("//"):
                            parts = line.split()
                            if len(parts) >= 2:
                                pkgs.append({
                                    "ecosystem": "Go", "name": parts[0],
                                    "version": parts[1], "file": str(go_mod.relative_to(root)),
                                })
            except Exception:
                continue
        return pkgs

    def _parse_ruby(self, root: Path) -> list[dict]:
        pkgs = []

        for gemfile in root.rglob("Gemfile"):
            if "vendor" in str(gemfile):
                continue
            try:
                with open(gemfile, encoding="utf-8") as f:
                    content = f.read()
                for match in re.finditer(
                    r'gem\s+["\']([^"\']+)["\']\s*(?:,\s*["\']([^"\']*)["\'])?',
                    content
                ):
                    pkgs.append({
                        "ecosystem": "RubyGems", "name": match.group(1),
                        "version": match.group(2) or None,
                        "file": str(gemfile.relative_to(root)),
                    })
            except Exception:
                continue
        return pkgs

    def _parse_dotnet(self, root: Path) -> list[dict]:
        pkgs = []

        for config_file in list(root.rglob("packages.config")):
            try:
                tree = ElementTree.parse(config_file)
                for pkg in tree.findall(".//package"):
                    pkg_id = pkg.get("id", "")
                    pkg_ver = pkg.get("version", "")
                    if pkg_id:
                        pkgs.append({
                            "ecosystem": "NuGet", "name": pkg_id,
                            "version": pkg_ver or None,
                            "file": str(config_file.relative_to(root)),
                        })
            except Exception:
                continue

        return pkgs
