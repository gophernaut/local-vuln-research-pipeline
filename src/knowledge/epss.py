"""EPSS (Exploit Prediction Scoring System) utilities.

EPSS provides probability that a CVE will be exploited in the next 30 days.
Data from: https://www.first.org/epss
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import sqlite3

from src.config import ROOT_DIR
from src.utils.logger import get_logger

DB_PATH = ROOT_DIR / "data" / "cve" / "nvd.sqlite"

logger = get_logger()


class EPSS:
    """Query EPSS scores from the unified CVE database."""

    def get_score(self, cve_id: str) -> dict[str, Any] | None:
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE id = ?",
            (cve_id,),
        ).fetchone()
        conn.close()
        if row and row[0] is not None:
            return {"score": row[0], "percentile": row[1]}
        return None

    def top_epss(self, limit: int = 100) -> list[dict[str, Any]]:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, description, epss_score, epss_percentile, cvss_score, kev_member "
            "FROM vulnerabilities WHERE epss_score IS NOT NULL "
            "ORDER BY epss_score DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def is_high_risk(self, cve_id: str, threshold: float = 0.10) -> bool:
        score = self.get_score(cve_id)
        return score is not None and score.get("score", 0) >= threshold
