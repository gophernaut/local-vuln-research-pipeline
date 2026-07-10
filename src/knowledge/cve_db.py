"""Query API for the unified CVE database.

Supports:
- FTS5 full-text search
- Semantic (embedding cosine) search via sentence-transformers
- Ranked by KEV > EPSS > public exploit > CVSS
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from src.config import ROOT_DIR, config
from src.utils.logger import get_logger

DB_PATH = ROOT_DIR / "data" / "cve" / "nvd.sqlite"

logger = get_logger()


class CVEDatabase:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self.conn: sqlite3.Connection | None = None
        self._embedder = None

    def _ensure_connection(self):
        if self.conn is None:
            if not self.db_path.exists():
                raise FileNotFoundError(
                    f"CVE database not found at {self.db_path}. "
                    f"Run: python -m src.main update-cve"
                )
            self.conn = sqlite3.connect(
                str(self.db_path), check_same_thread=False
            )
            self.conn.row_factory = sqlite3.Row

    def _ensure_embeddings(self):
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer(
                    config.get("knowledge.embedding_model", "all-MiniLM-L6-v2")
                )
            except ImportError:
                logger.warning("sentence-transformers not available. Semantic search disabled.")
                self._embedder = False

    def search(
        self,
        query: str,
        tech_stack: list[str] | None = None,
        cwe_ids: list[str] | None = None,
        ecosystem: str | None = None,
        limit: int = 20,
        min_epss: float | None = None,
        kev_only: bool = False,
    ) -> list[dict[str, Any]]:
        self._ensure_connection()

        results = []

        # FTS5 keyword search
        fts_matches = self._fts_search(query, limit=100)

        # Build result set with ranking
        for row in fts_matches:
            result = dict(row)
            result["_score"] = self._rank(row)
            results.append(result)

        # Filter
        if min_epss is not None:
            results = [r for r in results if (r.get("epss_score") or 0) >= min_epss]
        if kev_only:
            results = [r for r in results if r.get("kev_member") == 1]
        if tech_stack:
            results = [r for r in results if self._matches_tech(r, tech_stack)]
        if cwe_ids:
            results = [r for r in results if self._matches_cwes(r, cwe_ids)]
        if ecosystem:
            results = [r for r in results if r.get("package_ecosystem") == ecosystem]

        # Sort by ranking score
        results.sort(key=lambda r: r["_score"], reverse=True)
        return results[:limit]

    def lookup_package(
        self,
        package_name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_connection()

        rows = self.conn.execute(
            """SELECT * FROM vulnerabilities
            WHERE package_name LIKE ? AND package_ecosystem = ?
            ORDER BY kev_member DESC, epss_score DESC, cvss_score DESC
            LIMIT 50""",
            (f"%{package_name}%", ecosystem),
        ).fetchall()

        results = []
        for row in rows:
            r = dict(row)
            r["_score"] = self._rank(row)
            if version:
                if self._version_affected(r.get("affected_versions", ""), version):
                    results.append(r)
            else:
                results.append(r)
        return results

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        self._ensure_connection()
        row = self.conn.execute(
            "SELECT * FROM vulnerabilities WHERE id = ?", (cve_id,)
        ).fetchone()
        return dict(row) if row else None

    def stats(self) -> dict[str, Any]:
        self._ensure_connection()
        return {
            "total_cves": self.conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities"
            ).fetchone()[0],
            "kev_members": self.conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE kev_member = 1"
            ).fetchone()[0],
            "with_epss": self.conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE epss_score IS NOT NULL"
            ).fetchone()[0],
            "critical": self.conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'"
            ).fetchone()[0],
            "high": self.conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'HIGH'"
            ).fetchone()[0],
            "last_import": (
                self.conn.execute(
                    "SELECT value FROM meta WHERE key = 'last_import'"
                ).fetchone() or (None,)
            )[0],
        }

    def _fts_search(self, query: str, limit: int = 100) -> list[Any]:
        assert self.conn

        # Clean query for FTS5: remove chars that break FTS5 syntax
        clean = re.sub(r'[#\-\.,;:()\[\]{}!\"\'\\/]', ' ', query)
        clean = ' '.join(clean.split())

        if clean:
            try:
                rows = self.conn.execute(
                    """SELECT v.* FROM vulnerabilities v
                    JOIN vulnerabilities_fts fts ON v.rowid = fts.rowid
                    WHERE vulnerabilities_fts MATCH ?
                    ORDER BY v.kev_member DESC, v.epss_score DESC, v.cvss_score DESC
                    LIMIT ?""",
                    (clean, limit),
                ).fetchall()
                if rows:
                    return rows
            except sqlite3.OperationalError:
                pass

        # Fallback: OR-based LIKE for each word
        words = [w.strip() for w in clean.split() if len(w.strip()) > 1]
        if not words:
            words = [q for q in query.replace('#', ' ').split() if len(q) > 1]

        if words:
            placeholders = ' OR '.join(['description LIKE ?' for _ in words])
            params = [f'%{w}%' for w in words] + [limit]
            return self.conn.execute(
                f"""SELECT * FROM vulnerabilities
                WHERE ({placeholders})
                ORDER BY kev_member DESC, epss_score DESC, cvss_score DESC
                LIMIT ?""",
                params,
            ).fetchall()

        return []

    def _rank(self, row: sqlite3.Row) -> float:
        score = 0.0
        if row["kev_member"]:
            score += 1000
        epss = row["epss_score"] or 0
        score += epss * 500
        cvss = row["cvss_score"] or 0
        score += cvss * 5
        if row["has_public_exploit"]:
            score += 100
        return score

    def _matches_tech(self, row: dict, tech_stack: list[str]) -> bool:
        cpe = (row.get("cpe_matches") or "").lower()
        desc = (row.get("description") or "").lower()
        pkg_name = (row.get("package_name") or "").lower()
        combined = f"{cpe} {desc} {pkg_name}"
        return any(t.lower() in combined for t in tech_stack)

    def _matches_cwes(self, row: dict, cwe_ids: list[str]) -> bool:
        row_cwes = row.get("cwe_ids")
        if not row_cwes:
            return False
        try:
            cwe_list = json.loads(row_cwes)
        except (json.JSONDecodeError, TypeError):
            cwe_list = [row_cwes] if row_cwes else []
        return any(c in cwe_list for c in cwe_ids)

    def _version_affected(self, affected_str: str, version: str) -> bool:
        if not affected_str or not version:
            return False
        # Check if version is mentioned in affected range
        return version in affected_str

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
