"""Secrets scanner — detects hardcoded credentials, keys, and tokens.

gitleaks-compatible regex ruleset. Runs before any other analysis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class SecretMatch:
    file: str
    line: int
    rule_id: str
    category: str
    matched_text: str
    entropy: float = 0.0


SECRET_RULES = [
    ("aws-access-key", "AWS Access Key ID", r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", 0),
    ("aws-secret-key", "AWS Secret Access Key", r"(?i)aws.{0,20}(?:secret|pwd|password).{0,20}['\"]([A-Za-z0-9/+]{40})['\"]", 4.5),
    ("github-token", "GitHub Token", r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", 4.0),
    ("github-pat", "GitHub Personal Access Token", r"github_pat_[A-Za-z0-9_]{22,}", 4.0),
    ("google-api-key", "Google API Key", r"AIza[0-9A-Za-z\-_]{35}", 3.5),
    ("google-oauth", "Google OAuth Client ID", r"[0-9]+-[A-Z0-9a-z_]{32}\.apps\.googleusercontent\.com", 0),
    ("private-key", "Private Key (BEGIN)", r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", 0),
    ("jwt-secret", "Hardcoded JWT Secret", r"(?i)(?:jwt|jwt_secret|secret_key|secret).{0,10}['\"]([A-Za-z0-9\-_+/=]{20,})['\"]", 3.5),
    ("generic-password", "Hardcoded Password", r"(?i)(?:password|passwd|pwd).{0,10}['\"]([^'\"]{6,64})['\"]", 3.0),
    ("generic-api-key", "Generic API Key", r"(?i)(?:api[_-]?key|apikey).{0,10}['\"]([A-Za-z0-9\-_]{20,})['\"]", 3.5),
    ("generic-token", "Generic Token", r"(?i)(?:token|auth[_-]?token|access[_-]?token).{0,10}['\"]([A-Za-z0-9\-_/+]{16,})['\"]", 3.5),
    ("database-url", "Database Connection String", r"(?i)(?:mysql|postgres|mongodb|redis|sqlite)://[^@\s]+@[^\s]+", 0),
    ("slack-token", "Slack Token", r"xox[baprs]-[A-Za-z0-9\-]+", 3.5),
    ("slack-webhook", "Slack Webhook URL", r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", 0),
    ("stripe-key", "Stripe API Key", r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}", 3.5),
    ("npm-token", "npm Access Token", r"npm_[A-Za-z0-9]{36}", 3.5),
    ("pypi-token", "PyPI Token", r"pypi-[A-Za-z0-9\-_]{36,}", 3.5),
    ("heroku-key", "Heroku API Key", r"(?i)heroku.{0,20}[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}", 0),
    ("discord-token", "Discord Bot Token", r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}", 3.0),
    ("telegram-token", "Telegram Bot Token", r"\d{8,10}:AA[A-Za-z0-9\-_]{33}", 3.5),
    ("generic-secret", "Hardcoded Secret", r"(?i)(?:secret).{0,10}['\"]([^'\"]{10,})['\"]", 3.0),
    ("generic-credential", "Hardcoded Credential", r"(?i)(?:username|user).{0,10}['\"]([^'\"]+?)['\"].{0,20}(?:password|passwd|pwd).{0,10}['\"]([^'\"]+?)['\"]", 0),
    ("connection-string", "Connection String Pattern", r"(?i)(?:connection[_-]?string|conn[_-]?str).{0,10}['\"]([^'\"]{10,})['\"]", 0),
    ("dotenv-sensitive", "Sensitive .env Pattern", r"(?i)^\s*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIALS?)\s*=", 0),
    ("azure-storage-key", "Azure Storage Key", r"(?i)DefaultEndpointsProtocol=https.{0,200}AccountKey=[A-Za-z0-9+/=]{40,}", 3.5),
    ("azure-sas", "Azure SAS Token", r"(?i)(?:sig|signature)=[A-Za-z0-9%]{20,}", 3.0),
]


class SecretsScanner:
    def __init__(self):
        self.rules = []
        import math
        for rid, cat, pattern, ent in SECRET_RULES:
            try:
                self.rules.append({
                    "id": rid, "category": cat,
                    "regex": re.compile(pattern, re.IGNORECASE | re.MULTILINE),
                    "expected_entropy": ent,
                })
            except re.error:
                continue

    def scan(self, repo_path: Path) -> list[SecretMatch]:
        logger.info("Scanning for secrets...")
        all_matches: list[SecretMatch] = []

        text_extensions = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".java", ".c", ".h",
            ".cpp", ".cc", ".cxx", ".hpp", ".go", ".rs", ".cs", ".rb", ".php",
            ".swift", ".kt", ".scala", ".yaml", ".yml", ".json", ".xml", ".toml",
            ".ini", ".cfg", ".conf", ".env", ".properties", ".gradle", ".sh",
            ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".txt", ".md", ".rst",
            ".dockerfile", ".dockerignore", ".gitignore", ".gitattributes",
            ".sql", ".tf", ".hcl",
        }

        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                      "target", "build", "dist", "vendor", ".next", ".nuxt",
                      ".idea", ".vscode", "bin", "obj", "Debug", "Release"}

        for filepath in repo_path.rglob("*"):
            if not filepath.is_file():
                continue
            suffix = filepath.suffix.lower()
            name_lower = filepath.name.lower()

            has_text_ext = suffix in text_extensions
            is_named_config = name_lower in {".env", "dockerfile"} or name_lower.startswith("dockerfile")
            if not has_text_ext and not is_named_config:
                continue

            skip = any(d in filepath.parts for d in skip_dirs)
            if skip:
                continue

            try:
                if filepath.stat().st_size > 1024 * 1024:
                    continue
                with open(filepath, encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except Exception:
                continue

            matches = self._scan_text(source, str(filepath))
            all_matches.extend(matches)

        logger.info(f"  {len(all_matches)} secrets found")
        return all_matches

    def _scan_text(self, text: str, filepath: str) -> list[SecretMatch]:
        matches = []
        lines = text.split("\n")

        for rule in self.rules:
            for match in rule["regex"].finditer(text):
                start = match.start()
                line_num = text[:start].count("\n") + 1
                matched_text = match.group(0)

                entropy = self._shannon_entropy(matched_text)

                if rule["expected_entropy"] > 0 and entropy < rule["expected_entropy"] - 1.0:
                    continue

                # Exclude common false positives
                if self._is_false_positive(matched_text, filepath):
                    continue

                matches.append(SecretMatch(
                    file=filepath,
                    line=line_num,
                    rule_id=rule["id"],
                    category=rule["category"],
                    matched_text=matched_text,
                    entropy=round(entropy, 2),
                ))

        return matches

    def _shannon_entropy(self, data: str) -> float:
        import math
        if not data:
            return 0.0
        freq = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _is_false_positive(self, matched_text: str, filepath: str) -> bool:
        lower_text = matched_text.lower()
        fp_patterns = [
            "example", "sample", "test", "dummy", "fake", "mock",
            "placeholder", "your-key-here", "<key>", "<token>",
            "changeme", "replaceme", "todo", "xxxx", "0000",
            "your_", "your-", "my_", "my-",
        ]
        for fp in fp_patterns:
            if fp in lower_text:
                return True

        if filepath.endswith(".md") or filepath.endswith(".rst"):
            return True

        return False
