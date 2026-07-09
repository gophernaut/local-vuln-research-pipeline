"""File system and hashing utilities."""
from __future__ import annotations

import hashlib
from pathlib import Path


IGNORE_PATTERNS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".idea", ".vscode", "target", "build", "dist", ".gradle",
    "vendor", ".next", ".nuxt", "coverage", ".pytest_cache",
    "*.pyc", "*.pyo", "*.class", "*.o", "*.so", "*.dll",
    "*.exe", "*.dylib", "*.wasm", "*.min.js", "*.min.css",
    "*.map", "*.lock", "package-lock.json", "yarn.lock",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.zip", "*.tar", "*.gz", "*.bz2", "*.7z",
}


def collect_files(root: Path, max_size_mb: float = 5) -> list[Path]:
    files = []
    for f in root.rglob("*"):
        if _should_ignore(f, root):
            continue
        if f.is_file() and f.stat().st_size < max_size_mb * 1024 * 1024:
            files.append(f)
    return files


def _should_ignore(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    for part in rel.parts:
        if part in IGNORE_PATTERNS or part.startswith("."):
            return True
    suffix = path.suffix.lower()
    if f"*{suffix}" in IGNORE_PATTERNS:
        return True
    return False


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_tree_hash(repo_path: Path) -> str:
    files = sorted(collect_files(repo_path), key=lambda p: str(p))
    h = hashlib.sha256()
    for f in files:
        rel = f.relative_to(repo_path).as_posix()
        fh = file_hash(f)
        h.update(f"{rel}:{fh}\n".encode())
    return h.hexdigest()


def repo_checkpoint_key(repo_path: Path) -> str:
    h = hashlib.sha256()
    h.update(str(repo_path.resolve()).encode())

    try:
        import subprocess
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=repo_path, timeout=10
        )
        if result.returncode == 0:
            h.update(result.stdout.strip().encode())
            return h.hexdigest()
    except Exception:
        pass

    tree_hash = repo_tree_hash(repo_path)
    h.update(tree_hash.encode())
    return h.hexdigest()
