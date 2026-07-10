"""Embedding-based semantic search for CVE descriptions.

Uses all-MiniLM-L6-v2 (~80MB, CPU-friendly) to generate 384-dim embeddings
for hybrid keyword + semantic retrieval.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import numpy as np

from src.config import ROOT_DIR, config
from src.utils.logger import get_logger

DB_PATH = ROOT_DIR / "data" / "cve" / "nvd.sqlite"

logger = get_logger()


class EmbeddingIndex:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self._model = None

    def _ensure_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            model_name = config.get("knowledge.embedding_model", "all-MiniLM-L6-v2")
            logger.info(f"Loading embedding model: {model_name}")
            self._model = SentenceTransformer(model_name)
        return self._model

    def generate_all(self, batch_size: int = 256):
        """Generate embeddings for all CVEs that don't have one yet."""
        conn = sqlite3.connect(str(self.db_path))
        model = self._ensure_model()

        # Get CVEs without embeddings
        rows = conn.execute(
            "SELECT rowid, id, description FROM vulnerabilities "
            "WHERE description IS NOT NULL AND description_embedding IS NULL"
        ).fetchall()

        if not rows:
            logger.info("All CVEs already have embeddings.")
            conn.close()
            return

        logger.info(f"Generating embeddings for {len(rows)} CVEs...")

        descriptions = [r[2] or "" for r in rows]

        for i in range(0, len(descriptions), batch_size):
            batch = descriptions[i : i + batch_size]
            embeddings = model.encode(
                batch, batch_size=batch_size, show_progress_bar=False,
                normalize_embeddings=True,
            )
            for j, emb in enumerate(embeddings):
                rowid = rows[i + j][0]
                conn.execute(
                    "UPDATE vulnerabilities SET description_embedding = ? WHERE rowid = ?",
                    (emb.tobytes(), rowid),
                )
            conn.commit()
            if (i // batch_size) % 20 == 0:
                logger.info(f"  ... {min(i + batch_size, len(rows))}/{len(rows)}")

        conn.close()
        logger.info("Embedding generation complete.")

    def semantic_search(
        self,
        query: str,
        limit: int = 20,
        min_similarity: float = 0.3,
    ) -> list[dict[str, Any]]:
        """Search CVEs by semantic similarity to query text."""
        model = self._ensure_model()
        conn = sqlite3.connect(str(self.db_path))

        query_embedding = model.encode(
            [query], normalize_embeddings=True
        )[0]

        rows = conn.execute(
            "SELECT rowid, id, description, description_embedding, "
            "cvss_score, epss_score, kev_member "
            "FROM vulnerabilities WHERE description_embedding IS NOT NULL"
        ).fetchall()
        conn.close()

        if not rows:
            return []

        stored_embeddings = np.vstack([
            np.frombuffer(r[3], dtype=np.float32)
            for r in rows if r[3] is not None
        ])

        similarities = stored_embeddings.dot(query_embedding)

        results = []
        for i, row in enumerate(rows):
            emb_blob = row[3]
            if emb_blob is None:
                continue
            if i >= len(similarities):
                break
            sim = float(similarities[i])
            if sim >= min_similarity:
                results.append({
                    "id": row[1],
                    "description": row[2],
                    "similarity": sim,
                    "cvss_score": row[4],
                    "epss_score": row[5],
                    "kev_member": row[6],
                })

        results.sort(key=lambda r: (r["kev_member"] or 0) * 10 + r["similarity"], reverse=True)
        return results[:limit]
