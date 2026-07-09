"""Step 2: Dependency vulnerability scan.

Queries unified CVE/OSV/GHSA database for known vulns in project dependencies.
Ranked by: KEV > EPSS > public exploit > CVSS.
"""
from __future__ import annotations

from typing import Any

from src.knowledge.cve_db import CVEDatabase
from src.config import config
from src.utils.logger import get_logger

logger = get_logger()


def run(fingerprint: dict[str, Any]) -> list[dict[str, Any]]:
    logger.info("Step 2: Scanning dependencies for known vulnerabilities...")

    dependencies = fingerprint.get("dependencies", [])
    if not dependencies:
        logger.info("  No dependencies found. Skipping.")
        return []

    db = CVEDatabase()
    min_epss = config.get("thresholds.epss_min_score", 0.05)
    vulns = []

    dedup: set[str] = set()

    for dep in dependencies:
        eco = dep.get("ecosystem", "")
        name = dep.get("name", "")
        version = dep.get("version", "")

        if not name or not eco:
            continue

        results = db.lookup_package(name, eco, version)
        for r in results:
            cve_id = r.get("id", "")
            if cve_id in dedup:
                continue
            dedup.add(cve_id)

            epss = r.get("epss_score", 0) or 0
            kev = r.get("kev_member", 0)
            if epss >= min_epss or kev == 1:
                vulns.append({
                    "cve_id": cve_id,
                    "description": r.get("description", ""),
                    "cvss_score": r.get("cvss_score"),
                    "epss_score": epss,
                    "kev_member": kev,
                    "package": f"{eco}:{name}",
                    "version_used": version,
                    "severity": r.get("severity"),
                    "cwe_ids": r.get("cwe_ids"),
                })

    db.close()

    vulns.sort(key=lambda v: (v["kev_member"] * 10000) + (v["epss_score"] * 1000) + (v.get("cvss_score", 0) or 0), reverse=True)

    if vulns:
        kev_count = sum(1 for v in vulns if v["kev_member"])
        logger.info(f"  {len(vulns)} exploitable dep vulns ({kev_count} on CISA KEV)")
    else:
        logger.info("  No exploitable dependency vulns found")

    return vulns
