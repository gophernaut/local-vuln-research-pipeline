#!/usr/bin/env python3
"""Start llama-server with the uncensored model.

Usage: python start_server.py [--port 8080] [--threads 8] [--ncmoe 32] [--context 262144]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "models" / "Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ4_XS.gguf"
DOWNLOAD_URL = "https://huggingface.co/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive"


def main():
    parser = argparse.ArgumentParser(description="Start llama-server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--threads", "-t", type=int, default=8)
    parser.add_argument("--ncmoe", type=int, default=32, help="MoE experts on GPU")
    parser.add_argument("--context", "-c", type=int, default=262144, help="Context length")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--batch-size", "-b", type=int, default=1024)
    parser.add_argument("--ubatch-size", "-ub", type=int, default=512)
    args = parser.parse_args()

    if not MODEL_PATH.exists():
        print(f"[!] Model not found: {MODEL_PATH}")
        print(f"[!] Download from: {DOWNLOAD_URL}")
        print(f"[!] Place the IQ4_XS.gguf file in: {MODEL_PATH.parent}")
        sys.exit(1)

    print(f"[+] Starting llama-server on http://{args.host}:{args.port}")
    print(f"[+] Model: {MODEL_PATH.name}")
    print(f"[+] Context: {args.context:,} tokens | Threads: {args.threads} | NCMOE: {args.ncmoe}")

    cmd = [
        "llama-server",
        "-m", str(MODEL_PATH),
        "--host", args.host,
        "--port", str(args.port),
        "-ngl", "999",
        "-ncmoe", str(args.ncmoe),
        "--no-mmap",
        "-c", str(args.context),
        "--cache-type-k", "q4_0",
        "--cache-type-v", "q4_0",
        "--flash-attn", "on",
        "-t", str(args.threads),
        "-b", str(args.batch_size),
        "-ub", str(args.ubatch_size),
    ]

    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        print("[!] llama-server not found in PATH.")
        print("[!] Install llama.cpp or ensure llama-server is available.")
        print("[!] See: https://github.com/ggerganov/llama.cpp")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] Server stopped.")


if __name__ == "__main__":
    main()
