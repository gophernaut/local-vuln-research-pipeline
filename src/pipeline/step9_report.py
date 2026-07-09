"""Step 9: Report generation.

Produces report.md with root cause analysis, exploit path, runnable PoC,
real-world attack scenario, impact assessment, and remediation.
If no valid findings: outputs "TARGET EVALUATED AS SECURE".
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from src.llm.client import LLMClient
from src.llm.prompts import report_system
from src.utils.logger import get_logger

logger = get_logger()

REPORT_TEMPLATE = """## Summary

2-4 sentences explaining what the target does, what was found, and why it matters.

## Root Cause Analysis

Explain the root cause in natural language. Walk through the exploit path
with exact file:line references at each step.

## Proof of Concept

### Environment Setup
Exact commands to build and run the vulnerable target.

### Exploit Code
Actual runnable exploit code - curl, Python script, or crafted payload.

### Steps to Reproduce
Numbered steps with exact commands and expected output at each step.

## Real-World Attack Scenarios

At least one concrete attack scenario showing how this would be weaponized.

## Impact

Concrete damage description, not abstract CIA triad ratings.

## Remediation

Recommended fix with code diff where possible.

## Validation Checklist
- [ ] Attacker input from genuinely untrusted, externally accessible source
- [ ] Full code path traced from input to sink
- [ ] No hidden mitigations found
- [ ] Precondition Power Test passed
- [ ] Meets bug bounty rewardable bar
"""


def run(
    validated_findings: list[dict[str, Any]],
    repo_path: Path,
    output_path: Path | None = None,
) -> str:
    logger.info("Step 9: Generating report...")

    if not validated_findings:
        report = _generate_secure_report(repo_path)
        if output_path:
            output_path.write_text(report, encoding="utf-8")
        return report

    client = LLMClient()
    system = report_system(REPORT_TEMPLATE)

    for i, finding in enumerate(validated_findings[:2]):
        vuln_class = finding.get("vulnerability_class", "Unknown")
        logger.info(f"  Generating report for: {vuln_class}")

        trace_text = _format_trace(finding)
        user = (
            f"Target repository: {repo_path}\n\n"
            f"Vulnerability: {vuln_class}\n"
            f"CWE: {finding.get('cwe_id', 'N/A')}\n"
            f"Confidence: {finding.get('confidence', 0):.2f}\n\n"
            f"Exploit Path Trace:\n{trace_text}\n\n"
            f"Affected component: {finding.get('component', '')}\n"
            f"Entry point: {finding.get('entry_point', '')}\n"
            f"Sink: {finding.get('sink', '')}\n"
            f"Impact: {finding.get('impact', '')}\n"
            f"Preconditions: {finding.get('preconditions', [])}\n\n"
            f"Generate a complete vulnerability report following the template. "
            f"Include a RUNNABLE PoC with exact commands, setup, and expected output."
        )

        try:
            result = client.chat_json(system, user, max_tokens=4096)
            if result and "report_markdown" in result:
                report = result["report_markdown"]
            else:
                report = _generate_basic_report(finding, repo_path)
        except Exception as e:
            logger.warning(f"  Report generation failed: {e}")
            report = _generate_basic_report(finding, repo_path)

        if output_path:
            path = output_path if validated_findings.index(finding) == 0 else \
                output_path.parent / f"{output_path.stem}_{i + 1}{output_path.suffix}"
            path.write_text(report, encoding="utf-8")
            logger.info(f"  Report saved: {path}")

    final_report = f"# Vulnerability Report\n\n## Findings: {len(validated_findings)}\n\n"
    for finding in validated_findings:
        final_report += (
            f"- **{finding.get('vulnerability_class', 'Unknown')}** "
            f"(Confidence: {finding.get('confidence', 0):.2f}, "
            f"CWE: {finding.get('cwe_id', 'N/A')})\n"
        )

    return final_report


def _generate_secure_report(repo_path: Path) -> str:
    return (
        f"# Vulnerability Report\n\n"
        f"**Target:** `{repo_path}`\n\n"
        f"## Conclusion: TARGET EVALUATED AS SECURE\n\n"
        f"No exploitable HIGH or CRITICAL vulnerabilities were identified "
        f"in this codebase after full automated analysis.\n\n"
        f"### Analysis Summary\n"
        f"- Full static analysis (Semgrep + tree-sitter + sink detection) completed\n"
        f"- CVEs correlated against known exploit patterns for this tech stack\n"
        f"- Deep code tracing performed for candidate hypotheses\n"
        f"- All candidate findings eliminated by brutal filtering (Precondition Power Test, "
        f"reachability gate, trusted input reclassification, etc.)\n\n"
        f"### Limitations\n"
        f"- Analysis is static only, no dynamic testing performed\n"
        f"- Some vulnerability classes may require runtime context to detect\n"
        f"- Third-party dependencies should be independently monitored\n"
    )


def _format_trace(finding: dict[str, Any]) -> str:
    trace = finding.get("trace", [])
    if not trace:
        return "No detailed trace available."

    lines = []
    for hop in trace:
        if isinstance(hop, dict):
            lines.append(
                f"  Hop {hop.get('hop', '?')}: {hop.get('function', '')} @ "
                f"{hop.get('file', '?')}:{hop.get('line', '?')} - "
                f"{hop.get('description', '')} "
                f"[controlled: {hop.get('data_controlled', '?')}] "
                f"[mitigation: {hop.get('mitigation', 'none')}]"
            )
    return "\n".join(lines) if lines else str(trace)[:500]


def _generate_basic_report(finding: dict[str, Any], repo_path: Path) -> str:
    vuln = finding.get("vulnerability_class", "Unknown Vulnerability")
    cwe = finding.get("cwe_id", "N/A")
    entry = finding.get("entry_point", "unknown")
    sink = finding.get("sink", "unknown")
    impact = finding.get("impact", "unspecified")
    trace = _format_trace(finding)

    return (
        f"# Vulnerability Report\n\n"
        f"**Target:** `{repo_path}`\n"
        f"**Vulnerability:** {vuln}\n"
        f"**CWE:** {cwe}\n\n"
        f"## Summary\n\n"
        f"A {vuln} was identified in the target repository.\n\n"
        f"## Exploit Path\n\n{trace}\n\n"
        f"## Impact\n\n{impact}\n\n"
        f"## Validation Checklist\n"
        f"- [x] External attacker reachability verified\n"
        f"- [x] Precondition Power Test passed\n"
        f"- [x] No circular threat model\n"
        f"- [x] Meets bug bounty rewardable bar\n"
    )
