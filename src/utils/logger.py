"""Structured logging with file + console output."""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.config import config


def setup_logging(log_path: Path | None = None) -> logging.Logger:
    level = getattr(logging, config.get("logging.level", "INFO"), logging.INFO)

    logger = logging.getLogger("vulnresearch")
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-5s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(fmt)
    logger.addHandler(console)

    if log_path is None:
        log_path = Path(config.get("logging.file", "data/pipeline.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    logger = logging.getLogger("vulnresearch")
    if not logger.handlers:
        return setup_logging()
    return logger


def log_step(step: int, name: str, status: str, duration: float = 0.0, findings: str = ""):
    logger = get_logger()
    duration_str = f" ({duration:.1f}s)" if duration else ""
    findings_str = f" | {findings}" if findings else ""
    logger.info(f"Step {step} [{name}]: {status}{duration_str}{findings_str}")
