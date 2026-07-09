"""Step 4: CVE correlation — hybrid keyword + semantic search.

Maps relevant known CVE patterns to the target's tech stack and codebase.
Returns top CVEs ranked by KEV > EPSS > public exploit > CVSS.
"""
from __future__ import annotations

import json
from typing import Any

from src.knowledge.cve_db import CVEDatabase
from src.utils.logger import get_logger

logger = get_logger()


def run(
    fingerprint: dict[str, Any],
    classification: dict[str, Any],
    static_analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    logger.info("Step 4: Correlating CVE patterns...")

    query_parts = []

    primary_lang = fingerprint.get("primary_language", "")
    if primary_lang:
        query_parts.append(primary_lang)

    frameworks = fingerprint.get("frameworks", [])
    query_parts.extend(frameworks)

    cwe_ids = set()
    for sink in static_analysis.get("_sink_matches", []):
        cwe = sink.get("cwe_id", "")
        if cwe:
            cwe_ids.add(cwe)

    sink_categories = set(
        s.get("sink_category", "") for s in static_analysis.get("_taint_flows", [])
    )

    query_text = " ".join(query_parts)
    if not query_text:
        query_text = primary_lang or "web application"

    db = CVEDatabase()

    results = db.search(
        query=query_text,
        tech_stack=query_parts,
        cwe_ids=list(cwe_ids)[:20] if cwe_ids else None,
        limit=30,
        min_epss=0.01,
    )

    kev_entries = db.search(
        query=query_text,
        tech_stack=query_parts,
        kev_only=True,
        limit=10,
    )

    kev_ids = {r["id"] for r in kev_entries}
    for r in results:
        r["_is_kev"] = r["id"] in kev_ids
        if "_score" in r:
            r["rank_score"] = r.pop("_score")

    db.close()

    results.sort(
        key=lambda r: (
            (1 if r.get("kev_member") else 0) * 10000
            + (r.get("epss_score") or 0) * 1000
            + (r.get("cvss_score") or 0) * 5
        ),
        reverse=True,
    )

    top_20 = results[:20]

    if top_20:
        kev_count = sum(1 for r in top_20 if r.get("kev_member"))
        logger.info(f"  {len(top_20)} relevant CVEs ({kev_count} on CISA KEV)")
    else:
        logger.info("  No matching CVEs found in database. Run update-cve first.")

    formatted = []
    for r in top_20:
        formatted.append({
            "cve_id": r.get("id"),
            "description": r.get("description"),
            "cvss_score": r.get("cvss_score"),
            "epss_score": r.get("epss_score"),
            "kev_member": r.get("kev_member"),
            "cwe_ids": r.get("cwe_ids"),
            "severity": r.get("severity"),
            "rank_score": r.get("rank_score"),
        })

    return formatted
