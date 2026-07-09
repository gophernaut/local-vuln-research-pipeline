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
MODEL_PATH = ROOT / "models" / "Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ3_M.gguf"
DOWNLOAD_URL = "https://huggingface.co/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive"

QUANT_OPTIONS = {
    "iq3_m": ("Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ3_M.gguf", "15 GB, fits 16GB VRAM fully"),
    "iq4_xs": ("Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ4_XS.gguf", "19 GB, partial VRAM, PCIe expert misses"),
    "iq4_nl": ("Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-IQ4_NL.gguf", "20 GB, partial VRAM"),
    "q4_k_m": ("Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_M.gguf", "21 GB, heavy offloading"),
    "q4_k_p": ("Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_P.gguf", "23 GB, heavy offloading"),
}


def main():
    parser = argparse.ArgumentParser(description="Start llama-server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--threads", "-t", type=int, default=8)
    parser.add_argument("--ncmoe", type=int, default=24, help="MoE experts cached in VRAM (lower = more room for KV cache)")
    parser.add_argument("--context", "-c", type=int, default=49152, help="Context length. 16GB: 32-65K. 24GB: 65-131K.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--batch-size", "-b", type=int, default=2048)
    parser.add_argument("--ubatch-size", "-ub", type=int, default=512)
    parser.add_argument("--quant", choices=list(QUANT_OPTIONS.keys()), default="iq3_m",
                       help="Quantization to use")
    args = parser.parse_args()

    model_file = ROOT / "models" / QUANT_OPTIONS[args.quant][0]
    if not model_file.exists():
        print(f"[!] Model not found: {model_file}")
        print(f"[!] Download from: {DOWNLOAD_URL}")
        print(f"\nAvailable quants (size for 16GB VRAM):")
        for q, (fname, note) in QUANT_OPTIONS.items():
            print(f"  --quant {q:<10} {fname:<55} {note}")
        print(f"\nRecommended: --quant iq3_m  (fits fully in 16GB VRAM, no PCIe latency)")
        sys.exit(1)

    print(f"[+] Starting llama-server on http://{args.host}:{args.port}")
    print(f"[+] Model: {model_file.name}")
    print(f"[+] Quant: {args.quant}  ({QUANT_OPTIONS[args.quant][1]})")
    print(f"[+] Context: {args.context:,} tokens | Threads: {args.threads} | NCMOE: {args.ncmoe}")

    cmd = [
        "llama-server",
        "-m", str(model_file),
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
