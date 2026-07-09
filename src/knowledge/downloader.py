"""Download CVE data from NVD, OSV, GHSA, EPSS, and CISA KEV.

Sources:
- NVD CVE API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
- OSV.dev: https://osv.dev/ (ZIP dump or REST API)
- GHSA: https://github.com/github/advisory-database (git repo)
- EPSS: https://www.first.org/epss/data_stats
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterator

import requests

from src.config import ROOT_DIR, config
from src.utils.logger import get_logger

DATA_DIR = ROOT_DIR / "data" / "cve"
RAW_DIR = DATA_DIR / "raw"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/export"

logger = get_logger()


class CVEDownloader:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "LocalVulnResearch/1.0",
        })
        self.nvd_api_key = os.environ.get("NVD_API_KEY", "")
        RAW_DIR.mkdir(parents=True, exist_ok=True)

    def download_all(self):
        logger.info("Starting CVE data download from all sources...")
        self.download_nvd()
        self.download_epss()
        self.download_kev()
        self.download_ghsa()
        logger.info("All downloads complete")

    def download_nvd(self):
        logger.info("Downloading NVD CVE data...")
        last_mod_start = None
        total = 0
        page = 0
        results_per_page = 2000

        while True:
            page += 1
            start_index = (page - 1) * results_per_page

            params = {"resultsPerPage": results_per_page, "startIndex": start_index}
            if last_mod_start:
                params["lastModStartDate"] = last_mod_start

            try:
                req_kwargs = {"params": params, "timeout": 120}
                if self.nvd_api_key:
                    req_kwargs["headers"] = {"apiKey": self.nvd_api_key}

                # Retry up to 3 times on connection errors
                for attempt in range(3):
                    try:
                        resp = self.session.get(NVD_API, **req_kwargs)
                        break
                    except (requests.exceptions.ConnectionError,
                            requests.exceptions.ChunkedEncodingError,
                            requests.exceptions.Timeout) as conn_err:
                        if attempt < 2:
                            wait = (2 ** attempt) * 2
                            logger.warning(f"  Connection error, retrying in {wait}s: {conn_err}")
                            time.sleep(wait)
                        else:
                            raise conn_err
                if resp.status_code == 403:
                    logger.warning("NVD API rate limited. Use NVD_API_KEY env var for higher limits.")
                    break
                if resp.status_code == 404:
                    break
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.error(f"NVD request failed at page {page}: {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            out_path = RAW_DIR / f"nvd_page_{page:05d}.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)

            total += len(vulns)
            logger.info(f"  NVD page {page}: {len(vulns)} CVEs (total: {total})")

            if len(vulns) < results_per_page:
                break

            if not self.nvd_api_key:
                time.sleep(6)  # Rate limit: 5 req/30s without key
            else:
                time.sleep(0.1)  # Rate limit: 100 req/60s with key

        logger.info(f"NVD download complete: {total} CVEs across {page} pages")

    def download_epss(self):
        logger.info("Downloading EPSS scores...")
        out_path = RAW_DIR / "epss_scores.csv.gz"
        try:
            resp = self.session.get(EPSS_URL, timeout=180, stream=True)
            resp.raise_for_status()
            with open(out_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"EPSS downloaded: {out_path.stat().st_size / 1024 / 1024:.1f} MB")
        except Exception as e:
            logger.error(f"EPSS download failed: {e}")

    def download_kev(self):
        logger.info("Downloading CISA KEV catalog...")
        out_path = RAW_DIR / "kev.json"
        try:
            resp = self.session.get(KEV_URL, timeout=60)
            resp.raise_for_status()
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(resp.json(), f, ensure_ascii=False)
            vulns = resp.json().get("vulnerabilities", [])
            logger.info(f"KEV downloaded: {len(vulns)} known exploited vulns")
        except Exception as e:
            logger.error(f"KEV download failed: {e}")

    def download_ghsa(self):
        logger.info("Downloading GitHub Security Advisories...")
        ghsa_dir = RAW_DIR / "ghsa"
        if ghsa_dir.exists():
            logger.info("  GHSA already downloaded. Remove data/cve/raw/ghsa/ to re-download.")
            return

        try:
            import subprocess
            result = subprocess.run(
                [
                    "git", "clone", "--depth", "1", "--filter=blob:none",
                    "https://github.com/github/advisory-database.git",
                    str(ghsa_dir),
                ],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode == 0:
                logger.info("GHSA cloned successfully")
            else:
                logger.warning(f"GHSA clone warning: {result.stderr[:200]}")
                logger.info("  If git is not available, GHSA data will be skipped.")
        except FileNotFoundError:
            logger.warning("git not found. Skipping GHSA (git clone).")
        except Exception as e:
            logger.error(f"GHSA download failed: {e}")

    def download_osv(self):
        logger.info("Downloading OSV.dev data...")
        logger.info("  OSV provides per-ecosystem ZIP exports. Full download is large (~50GB).")
        logger.info("  For now, OSV queries are done via REST API on-demand during importer.")
        logger.info("  To add batch OSV, download from: https://osv.dev/docs/")
