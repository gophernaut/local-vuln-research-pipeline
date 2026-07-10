"""Attack graph builder — chains individual findings into multi-step exploits.

Builds a directed graph of findings where edges represent "A enables B."
Computes transitive closure via networkx: A → C is valid if A → B → C exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from src.analysis.path_analyze import PathAnalysisResult
from src.utils.logger import get_logger

logger = get_logger()

CHAIN_ROLES = {
    "command_execution": "code_exec",
    "sql_injection": "data_access",
    "ssrf": "internal_access",
    "path_traversal": "file_access",
    "deserialization": "code_exec",
    "file_write": "persistence",
    "file_read": "information_theft",
    "auth_bypass": "access_escalation",
    "hardcoded_secret": "credential_theft",
    "code_execution": "code_exec",
    "template_injection": "code_exec",
    "xxe": "data_access",
    "ldap_injection": "data_access",
    "xpath_injection": "data_access",
    "nosql_injection": "data_access",
    "spel_injection": "code_exec",
    "reflection_invoke": "code_exec",
    "buffer_overflow": "memory_corruption",
    "format_string": "memory_corruption",
    "weak_crypto": "crypto_failure",
    "weak_random": "crypto_failure",
    "race_condition": "logic_bypass",
    "toctou": "logic_bypass",
    "security_misconfig": "exposure",
    "object_injection": "code_exec",
    "code_injection": "code_exec",
}

ROLE_TRANSITIONS = {
    ("information_theft", "access_escalation"): "credential_reuse",
    ("information_theft", "internal_access"): "recon_to_ssrf",
    ("internal_access", "code_exec"): "SSRF to RCE",
    ("file_access", "code_exec"): "LFI to RCE",
    ("file_access", "information_theft"): "source_disclosure",
    ("persistence", "file_access"): "write_to_include",
    ("persistence", "code_exec"): "file_write_to_rce",
    ("data_access", "information_theft"): "data_exfiltration",
    ("data_access", "access_escalation"): "credential_extraction",
    ("access_escalation", "code_exec"): "privileged_execution",
    ("access_escalation", "data_access"): "admin_data_access",
    ("logic_bypass", "code_exec"): "race_to_rce",
    ("logic_bypass", "data_access"): "race_to_exfil",
    ("crypto_failure", "access_escalation"): "crypto_to_auth_bypass",
    ("crypto_failure", "information_theft"): "weak_crypto_exposure",
    ("credential_theft", "access_escalation"): "credential_to_bypass",
    ("credential_theft", "internal_access"): "credential_to_pivot",
    ("memory_corruption", "code_exec"): "memory_to_code_exec",
    ("exposure", "access_escalation"): "misconfig_to_bypass",
}

SEVERITY_VALUE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


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


def _get_role(finding: PathAnalysisResult) -> str:
    sink_parts = finding.sink.lower()
    for category, role in CHAIN_ROLES.items():
        if category in sink_parts:
            return role
    return "unknown"


def _severity_int(finding: PathAnalysisResult) -> int:
    return SEVERITY_VALUE.get(finding.severity.upper(), 0)


def build_attack_graph(findings: list[PathAnalysisResult]) -> list[ExploitChain]:
    logger.info(f"Building attack graph from {len(findings)} findings")

    exploitable = [f for f in findings if f.verdict == "VERIFIED_EXPLOITABLE"]
    if not exploitable:
        return []

    G = nx.DiGraph()

    for i, f in enumerate(exploitable):
        role = _get_role(f)
        G.add_node(i, finding=f, role=role, severity=_severity_int(f))

    for i in range(len(exploitable)):
        for j in range(len(exploitable)):
            if i == j:
                continue
            src_role = G.nodes[i]["role"]
            dst_role = G.nodes[j]["role"]
            transition = ROLE_TRANSITIONS.get((src_role, dst_role))
            if transition:
                G.add_edge(i, j, transition=transition, weight=0.7)

    chains = []

    for src in range(len(exploitable)):
        for dst in range(len(exploitable)):
            if src == dst or not nx.has_path(G, src, dst):
                continue

            try:
                shortest = nx.shortest_path(G, source=src, target=dst)
            except nx.NodeNotFound:
                continue

            if len(shortest) < 2:
                continue

            links = []
            confidences = []
            for idx in shortest:
                f = G.nodes[idx]["finding"]
                role = G.nodes[idx]["role"]
                links.append(ChainLink(
                    finding_id=f.path_id,
                    role=role,
                    description=f.exploit_scenario or f.reasoning,
                    file=f.file_path,
                    line=f.sink_line,
                    cwe_id=f.cwe_id,
                    severity=f.severity,
                    impact=f.sink or f.entry_point,
                ))
                confidences.append(f.confidence)

            max_sev = max(_severity_int(G.nodes[idx]["finding"]) for idx in shortest)
            sev_label = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(max_sev, "LOW")

            transition_names = []
            for k in range(len(shortest) - 1):
                edge = G.edges[shortest[k], shortest[k+1]]
                transition_names.append(edge["transition"])

            combined_conf = min(confidences) * (0.8 ** (len(shortest) - 1))
            first_f = G.nodes[shortest[0]]["finding"]
            last_f = G.nodes[shortest[-1]]["finding"]

            chains.append(ExploitChain(
                name=" -> ".join(transition_names),
                links=links,
                description=f"Multi-step chain: {first_f.cwe_id} → {last_f.cwe_id}",
                combined_impact="Remote Code Execution" if sev_label == "CRITICAL"
                    else "Privilege Escalation" if sev_label == "HIGH"
                    else "Data Exposure",
                combined_severity=sev_label,
                combined_confidence=round(combined_conf, 2),
                valid=True,
                entry_point=first_f.entry_point,
                final_impact=last_f.sink,
            ))

    unique_chains = []
    seen_ids = set()
    chains.sort(key=lambda c: c.combined_confidence, reverse=True)
    for chain in chains:
        link_ids = tuple(sorted(l.finding_id for l in chain.links))
        if link_ids not in seen_ids:
            seen_ids.add(link_ids)
            unique_chains.append(chain)

    logger.info(f"Attack graph: {len(unique_chains)} unique chains "
                f"across {len(set(v for c in unique_chains for v in [l.finding_id for l in c.links]))} findings")

    return unique_chains[:50]
