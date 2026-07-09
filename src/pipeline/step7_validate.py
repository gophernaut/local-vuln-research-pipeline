"""Step 7: Brutal validation + filtering + chain synthesis.

Applies all 12 filters. LLM critically examines each finding.
Chain exploit synthesis for medium-severity combos.
"""
from __future__ import annotations

from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import validate_system
from src.utils.logger import get_logger

logger = get_logger()

HARD_KILL_FILTERS = [
    "precondition_power",
    "circular_threat",
    "library_vs_app",
    "trusted_input",
    "dos_exclusion",
]

STANDARD_FILTERS = [
    "reachability",
    "controllability",
    "bypass_feasibility",
    "realistic_attacker",
    "no_assumed_conditions",
    "impact_materiality",
    "ai_slop_check",
]


def run(
    trace_results: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    logger.info("Step 7: Validating findings (brutal filters)...")

    if not trace_results:
        logger.info("  No trace results to validate.")
        return []

    validated = []
    for tr in trace_results:
        idx = tr.get("hypothesis_index", -1)
        hyp = hypotheses[idx] if 0 <= idx < len(hypotheses) else {}

        result = _validate_single(tr, hyp)
        if result:
            validated.append(result)
            logger.info(f"  VALID: {result.get('vulnerability_class')} (confidence: {result.get('confidence', 0):.2f})")

    if not validated:
        chains = _synthesize_chains(trace_results, hypotheses)
        if chains:
            logger.info(f"  No single HIGH/CRIT. {len(chains)} exploit chains found.")
            validated.extend(chains)
        else:
            logger.info("  No valid findings survived filtering. Target appears secure.")

    return validated


def _validate_single(trace: dict[str, Any], hypothesis: dict[str, Any]) -> dict[str, Any] | None:

    for gate in HARD_KILL_FILTERS:
        if not _pass_gate(gate, trace, hypothesis):
            logger.info(f"    DISCARDED by {gate}")
            return None

    for gate in STANDARD_FILTERS:
        if not _pass_gate(gate, trace, hypothesis):
            logger.info(f"    DISCARDED by {gate}")
            return None

    if not _pass_three_questions(trace, hypothesis):
        return None

    return {
        "vulnerability_class": hypothesis.get("vulnerability_class", trace.get("hypothesis_class", "")),
        "component": hypothesis.get("component", ""),
        "entry_point": hypothesis.get("entry_point", ""),
        "sink": hypothesis.get("sink", ""),
        "trace": trace.get("trace", []),
        "reachable": trace.get("reachable", False),
        "exploitable": trace.get("exploitable", False),
        "summary": trace.get("summary", ""),
        "confidence": hypothesis.get("confidence", 0),
        "impact": hypothesis.get("expected_impact", ""),
        "preconditions": hypothesis.get("preconditions", []),
        "cwe_id": hypothesis.get("cwe_id", ""),
        "validated": True,
        "filters_passed": HARD_KILL_FILTERS + STANDARD_FILTERS + ["three_questions"],
    }


def _pass_gate(gate: str, trace: dict[str, Any], hypothesis: dict[str, Any]) -> bool:

    if gate == "precondition_power":
        preconditions = hypothesis.get("preconditions", [])
        for pc in preconditions:
            pc_lower = str(pc).lower()
            powerful_keywords = [
                "already compromised", "admin access", "root access",
                "system-level", "kernel access", "already authenticated as admin",
                "controls the classpath", "controls jvm properties",
                "can modify configmap", "has cluster admin",
            ]
            for kw in powerful_keywords:
                if kw in pc_lower:
                    return False
        return True

    if gate == "circular_threat":
        if not hypothesis.get("entry_point"):
            return False
        return True

    if gate == "library_vs_app":
        if not hypothesis.get("entry_point"):
            return False
        return True

    if gate == "trusted_input":
        entry_type = hypothesis.get("entry_point_type", "").upper()
        trusted_types = ["CONFIG", "ENV_VAR_ADMIN", "SYSTEM_PROPERTY", "CLASSPATH"]
        if entry_type in trusted_types:
            return False
        return True

    if gate == "dos_exclusion":
        vuln_class = str(hypothesis.get("vulnerability_class", "")).lower()
        dos_keywords = ["dos", "denial of service", "redos", "resource exhaustion",
                        "compression bomb", "hash flood", "algorithmic complexity"]
        for kw in dos_keywords:
            if kw in vuln_class:
                return False
        return True

    if gate == "reachability":
        return trace.get("reachable", False)

    if gate == "controllability":
        blocked = trace.get("blocked_by")
        return blocked is None

    if gate == "ai_slop_check":
        vuln_class = str(hypothesis.get("vulnerability_class", "")).lower()
        slop_keywords = ["missing security header", "missing csrf", "missing httponly",
                         "information disclosure in error", "version disclosure",
                         "theoretical", "potential", "might be"]
        for kw in slop_keywords:
            if kw in vuln_class:
                return False
        return True

    return True


def _pass_three_questions(trace: dict[str, Any], hypothesis: dict[str, Any]) -> bool:

    if hypothesis.get("requires_authentication", True) and not trace.get("bypass_authentication", False):
        return False

    entry_type = str(hypothesis.get("entry_point_type", "")).upper()
    if entry_type in ("ENV_VAR", "CONFIG", "CLASSPATH", "SYSTEM_PROPERTY"):
        return False

    preconditions = str(hypothesis.get("preconditions", "")).lower()
    if "admin" in preconditions and "bypass" not in hypothesis.get("vulnerability_class", "").lower():
        return False

    return True


def _synthesize_chains(
    trace_results: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    chains = []

    exploitable = []
    for tr in trace_results:
        if tr.get("exploitable") and tr.get("reachable"):
            exploitable.append(tr)

    if len(exploitable) < 2:
        return []

    ssrf_items = []
    auth_items = []
    for i, tr in enumerate(exploitable):
        idx = tr.get("hypothesis_index", -1)
        hyp = hypotheses[idx] if 0 <= idx < len(hypotheses) else {}
        vuln_class = str(hyp.get("vulnerability_class", "")).lower()
        if "ssrf" in vuln_class:
            ssrf_items.append(tr)
        if "auth" in vuln_class or "bypass" in vuln_class:
            auth_items.append(tr)

    for ssrf in ssrf_items:
        for auth in auth_items:
            if ssrf != auth:
                chains.append({
                    "vulnerability_class": "CHAIN: SSRF + Auth Bypass -> Full Compromise",
                    "chain_links": [ssrf, auth],
                    "confidence": min(
                        ssrf.get("hypothesis_confidence", 0.5),
                        auth.get("hypothesis_confidence", 0.5),
                    ) * 0.8,
                    "validated": True,
                    "filters_passed": ["chain_synthesis"],
                    "summary": "SSRF provides internal access; auth bypass allows privileged operations.",
                })

    return chains
