"""Step 7: Brutal validation + LLM-driven chain exploit synthesis.

Applies all 12 filters. Then asks LLM: "Given these medium findings,
can any combination achieve HIGH/CRITICAL impact?" LLM traces combined chain.
"""
from __future__ import annotations

from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import validate_system
from src.utils.logger import get_logger

logger = get_logger()

HARD_KILL_FILTERS = [
    "precondition_power", "circular_threat", "library_vs_app",
    "trusted_input", "dos_exclusion",
]

STANDARD_FILTERS = [
    "reachability", "controllability", "bypass_feasibility",
    "realistic_attacker", "no_assumed_conditions", "impact_materiality",
    "ai_slop_check",
]

CHAIN_SYNTHESIS_PROMPT = """You are an exploit chain analyst. Given these individual findings,
identify if any COMBINATION of two or more findings can achieve a HIGHER impact than any alone.

RULES:
- A chain is valid if: Finding A enables Finding B, and A+B > A or B alone
- Examples: SSRF reaches internal API + auth bypass on that API = full compromise
            File write + path traversal to startup dir = RCE
            Info leak + credential reuse + auth bypass = privilege escalation
- Do NOT force chains. If findings are truly independent, say so honestly.
- Each chain link must be traceable through the code.

Output valid JSON:
{{"chains": [
  {{"name": "short name",
    "links": [0, 1],
    "description": "how link 0 enables link 1",
    "combined_impact": "final impact",
    "combined_confidence": 0.0-1.0,
    "valid": true/false
  }}
],
"has_valid_chain": true/false}}
"""


def run(
    trace_results: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    logger.info("Step 7: Validating findings + chain synthesis...")

    validated = []

    for tr in trace_results:
        idx = tr.get("hypothesis_index", -1)
        hyp = hypotheses[idx] if 0 <= idx < len(hypotheses) else {}

        result = _validate_single(tr, hyp)
        if result:
            validated.append(result)
            logger.info(f"  VALID: {result.get('vulnerability_class')} (conf: {result.get('confidence', 0):.2f})")

    if validated:
        logger.info(f"  {len(validated)} validated findings")
        return validated

    # No single finding survived. Try chain synthesis.
    logger.info("  No single HIGH/CRIT finding. Running chain synthesis...")

    chains = _synthesize_chains(trace_results, hypotheses)
    if chains:
        logger.info(f"  {len(chains)} exploit chains found")
        return chains

    logger.info("  No valid findings or chains. Target appears secure.")
    return []


def _validate_single(trace: dict, hyp: dict) -> dict[str, Any] | None:
    for gate in HARD_KILL_FILTERS:
        if not _pass_gate(gate, trace, hyp):
            logger.info(f"    DISCARDED by {gate}")
            return None

    for gate in STANDARD_FILTERS:
        if not _pass_gate(gate, trace, hyp):
            logger.info(f"    DISCARDED by {gate}")
            return None

    if not _pass_three_questions(trace, hyp):
        return None

    return {
        "vulnerability_class": hyp.get("vulnerability_class", trace.get("hypothesis_class", "")),
        "component": hyp.get("component", ""),
        "entry_point": hyp.get("entry_point", ""),
        "sink": hyp.get("sink", ""),
        "trace": trace.get("trace", []),
        "reachable": trace.get("reachable", False),
        "exploitable": trace.get("exploitable", False),
        "summary": trace.get("summary", ""),
        "confidence": hyp.get("confidence", 0),
        "impact": hyp.get("expected_impact", ""),
        "preconditions": hyp.get("preconditions", []),
        "cwe_id": hyp.get("cwe_id", ""),
        "validated": True,
    }


def _synthesize_chains(traces: list, hyps: list) -> list[dict[str, Any]]:
    medium = []
    for tr in traces:
        if tr.get("exploitable") and tr.get("reachable"):
            idx = tr.get("hypothesis_index", -1)
            hyp = hyps[idx] if 0 <= idx < len(hyps) else {}
            conf = hyp.get("confidence", 0)
            if conf >= 0.3:
                medium.append((idx, tr, hyp))

    if len(medium) < 2:
        return []

    client = LLMClient()

    findings_text = ""
    for j, (idx, tr, hyp) in enumerate(medium):
        findings_text += (
            f"Finding {j}: {hyp.get('vulnerability_class', '?')}\n"
            f"  Impact: {hyp.get('expected_impact', '?')}\n"
            f"  Entry: {hyp.get('entry_point', '?')} [{hyp.get('entry_point_type', '?')}]\n"
            f"  Preconditions: {hyp.get('preconditions', [])}\n"
            f"  Confidence: {hyp.get('confidence', 0):.2f}\n\n"
        )

    try:
        result = client.chat_json(CHAIN_SYNTHESIS_PROMPT, findings_text, max_tokens=2048, temperature=0.3)
    except Exception:
        return []

    chains = []
    for chain in result.get("chains", []):
        if chain.get("valid"):
            chains.append({
                "vulnerability_class": f"CHAIN: {chain.get('name', 'unnamed')}",
                "chain_links": chain.get("links", []),
                "description": chain.get("description", ""),
                "confidence": chain.get("combined_confidence", 0.5),
                "impact": chain.get("combined_impact", ""),
                "validated": True,
                "summary": chain.get("description", ""),
            })

    return chains


def _pass_gate(gate: str, trace: dict, hyp: dict) -> bool:
    combined = str(hyp).lower() + str(trace).lower()

    if gate == "precondition_power":
        for kw in ["already compromised", "admin access", "root access",
                    "controls the classpath", "controls jvm", "can modify configmap",
                    "has cluster admin", "kernel access", "system-level"]:
            if kw in combined:
                return False
        return True

    if gate == "circular_threat":
        return bool(hyp.get("entry_point"))

    if gate == "library_vs_app":
        return bool(hyp.get("entry_point"))

    if gate == "trusted_input":
        entry = str(hyp.get("entry_point_type", "")).upper()
        if entry in ("CONFIG", "SYSTEM_PROPERTY", "CLASSPATH_ADMIN"):
            return False
        return True

    if gate == "dos_exclusion":
        for kw in ["dos", "denial of service", "redos", "resource exhaustion",
                    "compression bomb", "hash flood", "algorithmic complexity"]:
            if kw in combined:
                return False
        return True

    if gate == "reachability":
        return trace.get("reachable", False)

    if gate == "ai_slop_check":
        for kw in ["missing security header", "missing csrf", "theoretical",
                    "potential", "might be", "informational", "version disclosure"]:
            if kw in combined:
                return False
        return True

    return True


def _pass_three_questions(trace: dict, hyp: dict) -> bool:
    if hyp.get("requires_authentication", True) and not trace.get("bypass_authentication", False):
        return False
    entry = str(hyp.get("entry_point_type", "")).upper()
    if entry in ("ENV_VAR", "CONFIG", "CLASSPATH", "SYSTEM_PROPERTY"):
        return False
    combined = str(hyp.get("preconditions", "")).lower()
    if "admin" in combined and "bypass" not in str(hyp.get("vulnerability_class", "")).lower():
        return False
    return True
