"""CISA Known Exploited Vulnerabilities (KEV) catalog.

Tracks CVEs with confirmed in-the-wild exploitation.
Data from: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import sqlite3

from src.config import ROOT_DIR
from src.utils.logger import get_logger

DB_PATH = ROOT_DIR / "data" / "cve" / "nvd.sqlite"

logger = get_logger()


class KEV:
    """Query CISA KEV membership from the unified CVE database."""

    def is_kev(self, cve_id: str) -> bool:
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT kev_member FROM vulnerabilities WHERE id = ?", (cve_id,)
        ).fetchone()
        conn.close()
        return row is not None and row[0] == 1

    def list_kev(self, ecosystem: str | None = None) -> list[dict[str, Any]]:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row

        if ecosystem:
            rows = conn.execute(
                "SELECT id, description, cvss_score, epss_score, cwe_ids "
                "FROM vulnerabilities WHERE kev_member = 1 AND package_ecosystem = ? "
                "ORDER BY cvss_score DESC",
                (ecosystem,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, description, cvss_score, epss_score, cwe_ids "
                "FROM vulnerabilities WHERE kev_member = 1 "
                "ORDER BY cvss_score DESC"
            ).fetchall()

        conn.close()
        return [dict(r) for r in rows]

    def kev_count(self) -> int:
        conn = sqlite3.connect(str(DB_PATH))
        count = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE kev_member = 1"
        ).fetchone()[0]
        conn.close()
        return count
