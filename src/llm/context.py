"""Context window management — chunking, dedup, code assembly for LLM prompts.

Handles: file chunking by function/class boundaries, context budget allocation,
deduplication of repeated code blocks across hypotheses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.config import config
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class CodeChunk:
    file: str
    start_line: int
    end_line: int
    content: str
    category: str = ""


class ContextManager:
    def __init__(self):
        self.context_limit = config.context_length
        self._sent_chunks: set[tuple[str, int, int]] = set()

    def allocate(
        self,
        system_prompt: str,
        cve_context: str = "",
        code_files: dict[str, str] | None = None,
    ) -> dict[str, str]:
        system_tokens = len(system_prompt) // 4
        cve_tokens = len(cve_context) // 4

        available = self.context_limit - system_tokens - cve_tokens - 1000

        if code_files is None:
            return {"system": system_prompt, "cve_context": cve_context, "code": ""}

        chunks: list[CodeChunk] = []
        for filepath, content in code_files.items():
            chunk = self._chunk_file(filepath, content, available // max(len(code_files), 1))
            if chunk:
                chunks.append(chunk)

        code_text = self._assemble_code(chunks, available)

        return {
            "system": system_prompt,
            "cve_context": cve_context,
            "code": code_text,
        }

    def _chunk_file(self, filepath: str, content: str, budget: int) -> CodeChunk | None:
        lines = content.split("\n")
        line_count = len(lines)

        if len(content) // 4 <= budget:
            return CodeChunk(
                file=filepath,
                start_line=1,
                end_line=line_count,
                content=content,
            )

        if line_count == 0:
            return None

        budget_lines = budget * 4

        with open(Path(filepath), encoding="utf-8", errors="replace") as f:
            pass

        try:
            import tree_sitter_python as tspy
            import tree_sitter as ts
            lang = tspy.language()
            parser = ts.Parser(ts.Language(lang))
            tree = parser.parse(content.encode("utf-8"))
            root = tree.root_node

            best_chunk = self._find_best_chunk(root, lines, budget_lines, content)
            if best_chunk:
                return best_chunk
        except Exception:
            pass

        truncated = "\n".join(lines[:budget_lines])
        return CodeChunk(
            file=filepath,
            start_line=1,
            end_line=min(budget_lines, line_count),
            content=truncated,
            category="truncated",
        )

    def _find_best_chunk(self, root, lines, budget_lines, source) -> CodeChunk | None:
        candidates = []
        for child in root.children:
            if child.type in ("function_definition", "class_definition", "method_definition"):
                start_line = child.start_point[0] + 1
                end_line = child.end_point[0] + 1
                chunk_lines = end_line - start_line + 1
                if chunk_lines <= budget_lines:
                    candidates.append((chunk_lines, start_line, end_line))

        if not candidates:
            return None

        candidates.sort(key=lambda c: c[0], reverse=True)

        combined_lines = 0
        start = candidates[0][1]
        end = candidates[0][2]
        combined_lines = end - start + 1

        for cl, s, e in candidates[1:]:
            if combined_lines + (e - s + 1) <= budget_lines:
                start = min(start, s)
                end = max(end, e)
                combined_lines = end - start + 1

        content = "\n".join(lines[start - 1 : end])
        return CodeChunk(
            file="",
            start_line=start,
            end_line=end,
            content=content,
        )

    def _assemble_code(self, chunks: list[CodeChunk], budget: int) -> str:
        parts = []
        used = 0

        for chunk in chunks:
            chunk_tokens = len(chunk.content) // 4
            if used + chunk_tokens > budget:
                break

            cache_key = (chunk.file, chunk.start_line, chunk.end_line)
            if cache_key in self._sent_chunks:
                continue

            self._sent_chunks.add(cache_key)

            parts.append(
                f"--- {chunk.file}:{chunk.start_line}-{chunk.end_line} ---\n"
                f"{chunk.content}\n"
            )
            used += chunk_tokens

        return "\n".join(parts)

    def reset_dedup(self):
        self._sent_chunks.clear()

    def prepare_code_bundle(
        self,
        files: list[Path],
        repo_root: Path,
        max_files: int = 10,
    ) -> dict[str, str]:
        code_files: dict[str, str] = {}
        for f in files[:max_files]:
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    code_files[str(f.relative_to(repo_root))] = fh.read()
            except Exception:
                continue
        return code_files
