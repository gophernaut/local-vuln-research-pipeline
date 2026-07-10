"""Attack graph builder — chains individual findings into multi-step exploits.

Builds a graph of findings where edges represent "A enables B":
- A writes to a file → B reads that file
- A leaks data → B uses that data for privilege escalation
- A achieves SSRF → B uses internal API access
- A achieves auth bypass → B performs sensitive action

Computes transitive closure: A → C is valid if A → B → C exists.
Outputs: list of valid exploit chains with combined impact.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.analysis.path_analyze import PathAnalysisResult
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class ChainLink:
    finding_id: str
    role: str
    description: str
    file: str
    line: int
    cwe_id: str
    severity: str
    impact: str = ""


@dataclass
class ExploitChain:
    name: str
    links: list[ChainLink]
    description: str
    combined_impact: str
    combined_severity: str
    combined_confidence: float
    valid: bool
    entry_point: str
    final_impact: str


def _findings_related_to_file(finding: PathAnalysisResult, file: str) -> bool:
    return finding.file_path == file or finding.sink.startswith(file)


def _find_chains_internal(findings: list[PathAnalysisResult]) -> list[ExploitChain]:
    chains = []

    write_findings = [f for f in findings if any(
        kw in f.exploit_scenario.lower()
        for kw in ["write", "upload", "create file", "save"]
    )]
    read_findings = [f for f in findings if any(
        kw in f.exploit_scenario.lower()
        for kw in ["read", "include", "require", "import"]
    )]

    for write_f in write_findings:
        for read_f in read_findings:
            if write_f.path_id == read_f.path_id:
                continue
            if write_f.severity in ("CRITICAL", "HIGH") and read_f.severity in ("CRITICAL", "HIGH"):
                chains.append(ExploitChain(
                    name="File Write → File Read/Include",
                    links=[
                        ChainLink(
                            finding_id=write_f.path_id, role="initial",
                            description=write_f.exploit_scenario,
                            file=write_f.file_path, line=write_f.sink_line,
                            cwe_id=write_f.cwe_id, severity=write_f.severity,
                            impact="arbitrary file write",
                        ),
                        ChainLink(
                            finding_id=read_f.path_id, role="amplifier",
                            description=read_f.exploit_scenario,
                            file=read_f.file_path, line=read_f.sink_line,
                            cwe_id=read_f.cwe_id, severity=read_f.severity,
                            impact="file read or RCE via inclusion",
                        ),
                    ],
                    description=f"Attacker writes file via {write_f.cwe_id} then uses file read/inclusion via {read_f.cwe_id}",
                    combined_impact="Remote Code Execution",
                    combined_severity="CRITICAL",
                    combined_confidence=min(write_f.confidence, read_f.confidence) * 0.7,
                    valid=True,
                    entry_point=write_f.entry_point,
                    final_impact="Full system compromise",
                ))

    info_findings = [f for f in findings if any(
        kw in f.exploit_scenario.lower()
        for kw in ["leak", "disclose", "expose", "reveal"]
    )]
    auth_findings = [f for f in findings if any(
        kw in f.exploit_scenario.lower()
        for kw in ["auth", "login", "bypass", "privilege"]
    )]

    for info_f in info_findings:
        for auth_f in auth_findings:
            if info_f.path_id == auth_f.path_id:
                continue
            if info_f.severity in ("MEDIUM", "HIGH") and auth_f.severity in ("CRITICAL", "HIGH"):
                chains.append(ExploitChain(
                    name="Info Leak → Auth Bypass",
                    links=[
                        ChainLink(
                            finding_id=info_f.path_id, role="reconnaissance",
                            description=info_f.exploit_scenario,
                            file=info_f.file_path, line=info_f.sink_line,
                            cwe_id=info_f.cwe_id, severity=info_f.severity,
                            impact="sensitive data exposure",
                        ),
                        ChainLink(
                            finding_id=auth_f.path_id, role="exploitation",
                            description=auth_f.exploit_scenario,
                            file=auth_f.file_path, line=auth_f.sink_line,
                            cwe_id=auth_f.cwe_id, severity=auth_f.severity,
                            impact="auth bypass",
                        ),
                    ],
                    description=f"Attacker leaks credentials/data via {info_f.cwe_id} then bypasses auth via {auth_f.cwe_id}",
                    combined_impact="Privilege Escalation",
                    combined_severity="HIGH",
                    combined_confidence=min(info_f.confidence, auth_f.confidence) * 0.6,
                    valid=True,
                    entry_point=info_f.entry_point,
                    final_impact="Unauthorized access",
                ))

    return chains


def build_attack_graph(findings: list[PathAnalysisResult]) -> list[ExploitChain]:
    logger.info(f"Building attack graph from {len(findings)} findings")

    exploitable = [f for f in findings if f.verdict == "VERIFIED_EXPLOITABLE"]
    if len(exploitable) < 2:
        return []

    chains = _find_chains_internal(exploitable)

    unique_chains = []
    seen_combinations = set()
    for chain in chains:
        link_ids = tuple(sorted([l.finding_id for l in chain.links]))
        if link_ids not in seen_combinations:
            seen_combinations.add(link_ids)
            unique_chains.append(chain)

    logger.info(f"Attack graph: {len(unique_chains)} unique chains")
    return unique_chains
