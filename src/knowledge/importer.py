"""Unified SQLite importer for NVD, EPSS, KEV data.

Schema: single vulnerabilities table + FTS5 index for hybrid keyword search.
Embeddings stored as BLOB for semantic (cosine) retrieval.
"""
from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path
from typing import Any

from src.config import ROOT_DIR, config
from src.utils.logger import get_logger

RAW_DIR = ROOT_DIR / "data" / "cve" / "raw"
DB_PATH = ROOT_DIR / "data" / "cve" / "nvd.sqlite"

logger = get_logger()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cvss_version TEXT,
    severity TEXT,
    cwe_ids TEXT,
    cpe_matches TEXT,
    package_name TEXT,
    package_ecosystem TEXT,
    affected_versions TEXT,
    fixed_versions TEXT,
    epss_score REAL,
    epss_percentile REAL,
    kev_member INTEGER DEFAULT 0,
    kev_date_added TEXT,
    has_public_exploit INTEGER DEFAULT 0,
    exploit_sources TEXT,
    published_date TEXT,
    modified_date TEXT,
    description_embedding BLOB
);

CREATE VIRTUAL TABLE IF NOT EXISTS vulnerabilities_fts USING fts5(
    id, description, cwe_ids, cpe_matches, package_name, package_ecosystem,
    content='vulnerabilities', content_rowid='rowid'
);

CREATE INDEX IF NOT EXISTS idx_cvss ON vulnerabilities(cvss_score);
CREATE INDEX IF NOT EXISTS idx_epss ON vulnerabilities(epss_score);
CREATE INDEX IF NOT EXISTS idx_kev ON vulnerabilities(kev_member);
CREATE INDEX IF NOT EXISTS idx_package ON vulnerabilities(package_name, package_ecosystem);
CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class CVEImporter:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: sqlite3.Connection | None = None
        self._kev_set: set[str] = set()
        self._epss_data: dict[str, dict] = {}

    def import_all(self):
        self._open()
        self._init_schema()
        self._load_epss()
        self._load_kev()
        self._import_nvd()
        self._update_fts()
        self._update_meta()
        self._close()
        logger.info(f"Import complete. DB: {self.db_path}")

    def _open(self):
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.execute("PRAGMA cache_size=-64000")

    def _close(self):
        if self.conn:
            self.conn.commit()
            self.conn.close()
            self.conn = None

    def _init_schema(self):
        assert self.conn
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def _load_epss(self):
        epss_path = RAW_DIR / "epss_scores.csv.gz"
        if not epss_path.exists():
            logger.warning("EPSS data not found. Skipping.")
            return

        logger.info("Loading EPSS scores...")
        count = 0
        with gzip.open(epss_path, "rt", encoding="utf-8") as f:
            header = f.readline().strip().split(",")
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 3:
                    cve = parts[0].strip()
                    try:
                        score = float(parts[1])
                        percentile = float(parts[2])
                        self._epss_data[cve] = {"score": score, "percentile": percentile}
                        count += 1
                    except ValueError:
                        pass
        logger.info(f"  {count} EPSS scores loaded")

    def _load_kev(self):
        kev_path = RAW_DIR / "kev.json"
        if not kev_path.exists():
            logger.warning("KEV data not found. Skipping.")
            return

        logger.info("Loading CISA KEV...")
        with open(kev_path, encoding="utf-8") as f:
            data = json.load(f)

        for v in data.get("vulnerabilities", []):
            cve_id = v.get("cveID", "")
            if cve_id:
                self._kev_set.add(cve_id)
        logger.info(f"  {len(self._kev_set)} KEV entries loaded")

    def _import_nvd(self):
        nvd_files = sorted(
            p for p in Path(RAW_DIR).glob("nvd_page_*.json")
            if p.stat().st_size > 0
        )
        if not nvd_files:
            logger.warning("No NVD page files found. Skipping NVD import.")
            return

        logger.info(f"Importing {len(nvd_files)} NVD page files...")
        total, imported = 0, 0

        for nvd_file in nvd_files:
            try:
                with open(nvd_file, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                logger.error(f"  Failed to read {nvd_file.name}: {e}")
                continue

            for vuln in data.get("vulnerabilities", []):
                total += 1
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue

                metrics = self._extract_cvss(cve_data)
                cwes = self._extract_cwes(cve_data)
                cpe_text = self._extract_cpes(cve_data)
                desc_text = self._extract_description(cve_data)

                published = cve_data.get("published", "")
                modified = cve_data.get("lastModified", "")

                epss = self._epss_data.get(cve_id, {})
                epss_score = epss.get("score")
                epss_pct = epss.get("percentile")
                kev_member = 1 if cve_id in self._kev_set else 0

                self._upsert_vuln(
                    cve_id=cve_id,
                    source="NVD",
                    description=desc_text,
                    cvss_score=metrics.get("score"),
                    cvss_vector=metrics.get("vector"),
                    cvss_version=metrics.get("version"),
                    severity=metrics.get("severity"),
                    cwe_ids=json.dumps(cwes) if cwes else None,
                    cpe_matches=cpe_text,
                    epss_score=epss_score,
                    epss_percentile=epss_pct,
                    kev_member=kev_member,
                    published_date=published,
                    modified_date=modified,
                )
                imported += 1

            if imported > 0 and imported % 5000 == 0:
                self.conn.commit()
                logger.info(f"  ... {imported} CVEs imported so far (total scanned: {total})")

        self.conn.commit()
        logger.info(f"NVD import complete: {imported} CVEs (scanned {total})")

    def _extract_cvss(self, cve_data: dict) -> dict:
        metrics = cve_data.get("metrics", {})
        for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            entries = metrics.get(version, [])
            if entries:
                cvss = entries[0].get("cvssData", {})
                cvss_version = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1",
                                 "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}.get(version, "")
                return {
                    "score": cvss.get("baseScore"),
                    "vector": cvss.get("vectorString"),
                    "severity": cvss.get("baseSeverity", "").upper(),
                    "version": cvss_version,
                }
        return {}

    def _extract_cwes(self, cve_data: dict) -> list[str]:
        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwes.append(value)
        return cwes

    def _extract_cpes(self, cve_data: dict) -> str | None:
        configs = cve_data.get("configurations", [])
        cpe_parts = []
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    crit = match.get("criteria", "")
                    if crit:
                        cpe_parts.append(crit)
        return ", ".join(cpe_parts[:50]) if cpe_parts else None

    def _extract_description(self, cve_data: dict) -> str | None:
        descs = cve_data.get("descriptions", [])
        for d in descs:
            if d.get("lang") == "en":
                return d.get("value", "")
        return descs[0].get("value", "") if descs else None

    def _upsert_vuln(self, cve_id: str, **kwargs):
        assert self.conn
        self.conn.execute(
            """INSERT OR REPLACE INTO vulnerabilities
            (id, source, description, cvss_score, cvss_vector, cvss_version, severity,
             cwe_ids, cpe_matches, package_name, package_ecosystem,
             affected_versions, fixed_versions,
             epss_score, epss_percentile, kev_member, kev_date_added,
             has_public_exploit, exploit_sources,
             published_date, modified_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cve_id,
                kwargs.get("source"),
                kwargs.get("description"),
                kwargs.get("cvss_score"),
                kwargs.get("cvss_vector"),
                kwargs.get("cvss_version"),
                kwargs.get("severity"),
                kwargs.get("cwe_ids"),
                kwargs.get("cpe_matches"),
                kwargs.get("package_name"),
                kwargs.get("package_ecosystem"),
                kwargs.get("affected_versions"),
                kwargs.get("fixed_versions"),
                kwargs.get("epss_score"),
                kwargs.get("epss_percentile"),
                kwargs.get("kev_member", 0),
                kwargs.get("kev_date_added"),
                kwargs.get("has_public_exploit", 0),
                kwargs.get("exploit_sources"),
                kwargs.get("published_date"),
                kwargs.get("modified_date"),
            ),
        )

    def _update_fts(self):
        assert self.conn
        logger.info("Updating FTS index...")
        self.conn.execute(
            "INSERT INTO vulnerabilities_fts(vulnerabilities_fts) VALUES ('rebuild')"
        )
        self.conn.commit()

    def _update_meta(self):
        assert self.conn
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_import', ?)", (now,))
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)", ("1",))
        self.conn.commit()
