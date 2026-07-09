"""OpenAI-compatible API client for llama-server.

Handles connection, retries, JSON parsing with repair, and self-consistency.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from openai import OpenAI, APIError, RateLimitError, APIConnectionError

from src.config import config
from src.utils.logger import get_logger

logger = get_logger()


class LLMClient:
    def __init__(self):
        port = config.get("server.port", 8080)
        self.base_url = f"http://127.0.0.1:{port}/v1"
        self.client = OpenAI(base_url=self.base_url, api_key="not-needed")
        self.max_retries = 3
        self.retry_delay = 2.0
        self._model_name = "local-model"

    def chat(
        self,
        system: str,
        user: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

        extra: dict[str, Any] = {}
        if json_mode:
            extra["response_format"] = {"type": "json_object"}

        for attempt in range(self.max_retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self._model_name,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **extra,
                )
                content = resp.choices[0].message.content or ""
                return content.strip()
            except (APIConnectionError, RateLimitError) as e:
                wait = self.retry_delay * (2 ** attempt)
                logger.warning(f"LLM API error (attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(wait)
                else:
                    raise ConnectionError(f"LLM connection failed after {self.max_retries} attempts: {e}")
            except APIError as e:
                logger.error(f"LLM API error: {e}")
                raise

        return ""

    def chat_json(
        self,
        system: str,
        user: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> dict[str, Any] | list[Any]:
        raw = self.chat(system, user, temperature, max_tokens, json_mode=True)
        parsed = self._parse_json(raw)
        if parsed is None:
            raw = self.chat(system, user, temperature, max_tokens)
            parsed = self._parse_json(raw)
        if parsed is None:
            return {}
        return parsed

    def self_consistent(
        self,
        system: str,
        user: str,
        runs: int = 3,
        temperature: float = 0.3,
        agreement_threshold: float = 0.66,
    ) -> dict[str, Any] | None:
        results = []
        for _ in range(runs):
            result = self.chat_json(system, user, temperature)
            if result:
                results.append(result)

        if not results:
            return None

        if len(results) == 1:
            return results[0]

        agreement_count = sum(
            1 for r in results
            if self._results_agree(r, results[0])
        )
        if agreement_count / len(results) >= agreement_threshold:
            return results[0]

        return None

    def _parse_json(self, text: str) -> dict | list | None:
        if not text:
            return None

        text = text.strip()

        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]

        if text.endswith("```"):
            text = text[:-3]

        text = text.strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        try:
            match = re.search(r"\{[\s\S]*\}", text)
            if match:
                return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

        try:
            match = re.search(r"\[[\s\S]*\]", text)
            if match:
                return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

        return None

    def _results_agree(self, a: dict, b: dict) -> bool:
        a_class = str(a.get("vulnerability_class", "") or a.get("class", ""))
        b_class = str(b.get("vulnerability_class", "") or b.get("class", ""))
        return a_class == b_class

    def health_check(self) -> bool:
        try:
            self.client.models.list()
            return True
        except Exception:
            return False

    def estimate_tokens(self, text: str) -> int:
        return len(text) // 4
