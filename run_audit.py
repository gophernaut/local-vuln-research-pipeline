#!/usr/bin/env python3
"""Audit a target repository.

Usage: python run_audit.py <repo_path> [--resume]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Audit a repository for vulnerabilities")
    parser.add_argument("repo_path", help="Path to target repository")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    args = parser.parse_args()

    target = Path(args.repo_path).resolve()
    if not target.exists():
        print(f"[!] Repository not found: {target}")
        sys.exit(1)

    print(f"[+] Auditing: {target}")

    cmd = [sys.executable, "-m", "src.main", "audit", str(target)]
    if args.resume:
        cmd.append("--resume")

    result = subprocess.run(cmd, cwd=Path(__file__).resolve().parent)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
