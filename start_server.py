#!/usr/bin/env python3
"""Start llama-server with code-specialized abliterated model + speculative decoding.

Usage: python start_server.py [--port 8080] [--threads 8] [--context 131072] [--speculative]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

MODEL_FILE = ROOT / "models" / "Qwen2.5-Coder-7B-Instruct-abliterated-Q6_K.gguf"
DRAFT_FILE = ROOT / "models" / "Qwen2.5-Coder-0.5B-Instruct-abliterated-Q4_K_M.gguf"
MODEL_URL = "https://huggingface.co/bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF"
DRAFT_URL = "https://huggingface.co/bartowski/Qwen2.5-Coder-0.5B-Instruct-abliterated-GGUF"


def main():
    parser = argparse.ArgumentParser(description="Start llama-server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--threads", "-t", type=int, default=8)
    parser.add_argument("--context", "-c", type=int, default=131072, help="Context length (131K recommended for 7B)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--batch-size", "-b", type=int, default=2048)
    parser.add_argument("--ubatch-size", "-ub", type=int, default=512)
    parser.add_argument("--no-speculative", action="store_true", help="Disable speculative decoding")
    args = parser.parse_args()

    if not MODEL_FILE.exists():
        print(f"[!] Model not found: {MODEL_FILE}")
        print(f"[!] Download from: {MODEL_URL}")
        print(f"[!] Command: huggingface-cli download bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF Qwen2.5-Coder-7B-Instruct-abliterated-Q6_K.gguf --local-dir models/")
        sys.exit(1)

    use_speculative = not args.no_speculative and DRAFT_FILE.exists()
    if not args.no_speculative and not DRAFT_FILE.exists():
        print(f"[!] Draft model not found: {DRAFT_FILE}")
        print(f"[!] Download from: {DRAFT_URL}")
        print(f"[+] Running without speculative decoding")

    print(f"[+] Starting llama-server on http://{args.host}:{args.port}")
    print(f"[+] Model:  Qwen2.5-Coder-7B-Abliterated Q6_K (7B dense, 6.25GB)")
    print(f"[+] Context: {args.context:,} tokens | Threads: {args.threads}")
    if use_speculative:
        print(f"[+] Draft:   Qwen2.5-Coder-0.5B Q4_K_M (~400MB) — speculative decoding ENABLED")
    else:
        print(f"[+] Draft:   NOT USED — speculative decoding DISABLED")

    cmd = [
        "llama-server",
        "-m", str(MODEL_FILE),
        "--host", args.host,
        "--port", str(args.port),
        "-ngl", "999",
        "--no-mmap",
        "-c", str(args.context),
        "--cache-type-k", "q4_0",
        "--cache-type-v", "q4_0",
        "--flash-attn", "on",
        "--jinja",
        "-t", str(args.threads),
        "-b", str(args.batch_size),
        "-ub", str(args.ubatch_size),
    ]

    if use_speculative:
        cmd.extend([
            "--model-draft", str(DRAFT_FILE),
            "--spec-draft-n-max", "16",
            "--spec-draft-n-min", "0",
            "--spec-draft-p-min", "0.0",
            "--spec-draft-p-split", "0.1",
        ])

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
