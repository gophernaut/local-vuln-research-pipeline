#!/usr/bin/env python3
"""Run model benchmark to determine optimal settings.

Usage: python run_benchmark.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main():
    print("[+] Running model benchmark...")
    print("[!] Make sure llama-server is running first: python start_server.py")
    print()

    result = subprocess.run(
        [sys.executable, "-m", "src.main", "benchmark"],
        cwd=Path(__file__).resolve().parent,
    )

    if result.returncode == 0:
        print("\n[+] Check config.yaml for updated AUTO values")
    else:
        print("\n[!] Benchmark failed. Is llama-server running?")

    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
