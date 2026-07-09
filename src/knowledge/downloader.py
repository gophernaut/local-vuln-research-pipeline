"""Download CVE data from NVD, EPSS, and CISA KEV.

Sources:
- NVD CVE API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
- EPSS: https://www.first.org/epss/data_stats
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

from src.config import ROOT_DIR
from src.utils.logger import get_logger

DATA_DIR = ROOT_DIR / "data" / "cve"
RAW_DIR = DATA_DIR / "raw"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

logger = get_logger()


class CVEDownloader:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "LocalVulnResearch/1.0"})
        self.nvd_api_key = os.environ.get("NVD_API_KEY", "")
        RAW_DIR.mkdir(parents=True, exist_ok=True)

    def download_all(self):
        logger.info("Downloading CVE data (NVD + EPSS + KEV)...")
        self.download_nvd()
        self.download_epss()
        self.download_kev()
        logger.info("All downloads complete")

    def download_nvd(self):
        logger.info("Downloading NVD CVE data...")
        total = 0
        page = 0
        results_per_page = 2000

        while True:
            page += 1
            start_index = (page - 1) * results_per_page
            params = {"resultsPerPage": results_per_page, "startIndex": start_index}

            req_kwargs: dict = {"params": params, "timeout": 120}
            if self.nvd_api_key:
                req_kwargs["headers"] = {"apiKey": self.nvd_api_key}

            for attempt in range(3):
                try:
                    resp = self.session.get(NVD_API, **req_kwargs)
                    break
                except (requests.exceptions.ConnectionError,
                        requests.exceptions.ChunkedEncodingError,
                        requests.exceptions.Timeout) as conn_err:
                    if attempt < 2:
                        wait = (2 ** attempt) * 2
                        logger.warning(f"  Retry {attempt+1}/3 in {wait}s: {conn_err}")
                        time.sleep(wait)
                    else:
                        logger.error(f"NVD request failed at page {page}: {conn_err}")
                        logger.info(f"NVD partial: {total} CVEs across {page - 1} pages")
                        return

            if resp.status_code == 403:
                logger.warning("NVD rate limited. Set NVD_API_KEY env var for higher limits.")
                break
            if resp.status_code == 404:
                break
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            out_path = RAW_DIR / f"nvd_page_{page:05d}.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)

            total += len(vulns)
            if page % 10 == 0 or page == 1:
                logger.info(f"  NVD page {page}: {total:,} CVEs total")

            if len(vulns) < results_per_page:
                break

            if self.nvd_api_key:
                time.sleep(0.3)
            else:
                time.sleep(6)

        logger.info(f"NVD download complete: {total:,} CVEs across {page} pages")

    def download_epss(self):
        logger.info("Downloading EPSS scores...")
        out_path = RAW_DIR / "epss_scores.csv.gz"
        try:
            resp = self.session.get(EPSS_URL, timeout=180, stream=True)
            resp.raise_for_status()
            with open(out_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"  EPSS: {out_path.stat().st_size / 1024 / 1024:.1f} MB")
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
            logger.info(f"  KEV: {len(vulns)} known exploited vulns")
        except Exception as e:
            logger.error(f"KEV download failed: {e}")
