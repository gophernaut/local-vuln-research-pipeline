#!/usr/bin/env python3
"""Start llama-server with a code-specialized abliterated model + speculative decoding.

Reads model paths from config.yaml so switching models is a one-line config change.

Usage: python start_server.py [--port 8080] [--threads 8] [--context 32768] [--no-speculative]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _read_config():
    try:
        import yaml
        with open(ROOT / "config.yaml") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


def main():
    cfg = _read_config()

    model_file = ROOT / cfg.get("model", {}).get("file", "models/model.gguf")
    draft_file = ROOT / cfg.get("model", {}).get("draft_file", "")
    model_name = cfg.get("model", {}).get("name", "Unknown")
    model_quant = cfg.get("model", {}).get("quant", "")
    context_default = cfg.get("server", {}).get("context_length", 32768)

    parser = argparse.ArgumentParser(description="Start llama-server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--threads", "-t", type=int, default=8)
    parser.add_argument("--context", "-c", type=int, default=context_default)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--batch-size", "-b", type=int, default=2048)
    parser.add_argument("--ubatch-size", "-ub", type=int, default=512)
    parser.add_argument("--no-speculative", action="store_true", help="Disable speculative decoding")
    args = parser.parse_args()

    if not model_file.exists():
        print(f"[!] Model not found: {model_file}")
        print(f"[!] Download from: {cfg.get('model', {}).get('download_url', 'https://huggingface.co/bartowski')}")
        print(f"[!] Check config.yaml model.file path")
        sys.exit(1)

    use_speculative = not args.no_speculative and draft_file.exists()
    if not args.no_speculative and not draft_file.exists():
        print(f"[!] Draft model not found: {draft_file}")
        print(f"[+] Running without speculative decoding")

    model_size_mb = model_file.stat().st_size / (1024 * 1024) if model_file.exists() else 0
    draft_size_mb = draft_file.stat().st_size / (1024 * 1024) if draft_file.exists() else 0
    vram = (model_size_mb + draft_size_mb) / 1024 if use_speculative else model_size_mb / 1024

    print(f"[+] Starting llama-server on http://{args.host}:{args.port}")
    print(f"[+] Model:  {model_name} {model_quant} ({model_size_mb:.0f} MB, {vram:.1f} GB VRAM)")
    print(f"[+] Context: {args.context:,} tokens | Threads: {args.threads}")
    if use_speculative:
        print(f"[+] Draft:  0.5B draft ({draft_size_mb:.0f} MB) — speculative decoding ENABLED")
    else:
        print(f"[+] Draft:  NOT USED — speculative decoding DISABLED")

    cmd = [
        "llama-server",
        "-m", str(model_file),
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
            "--model-draft", str(draft_file),
            "--spec-draft-n-max", "16",
            "--spec-draft-n-min", "0",
            "--spec-draft-p-min", "0.0",
            "--spec-draft-p-split", "0.1",
        ])

    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        print("[!] llama-server not found in PATH.")
        print("[!] Install llama.cpp: https://github.com/ggerganov/llama.cpp")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[+] Server stopped.")


if __name__ == "__main__":
    main()
