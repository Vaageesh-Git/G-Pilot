from __future__ import annotations

import json
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from vuln_swarm.core.config import Settings
from vuln_swarm.core.json_utils import validate_agent_json

ModelT = TypeVar("ModelT", bound=BaseModel)


class LlmUnavailableError(RuntimeError):
    pass


class GroqJsonClient:
    """Small OpenAI-compatible Groq client optimized for strict JSON agent contracts."""

    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.groq_api_key)

    async def complete_json(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        output_model: type[ModelT],
        schema_name: str,
    ) -> ModelT:
        if not self.settings.groq_api_key:
            raise LlmUnavailableError("GROQ_API_KEY is not configured")

        schema = output_model.model_json_schema()
        messages = [
            {
                "role": "system",
                "content": (
                    f"{system_prompt}\n\n"
                    "Return only a strict JSON object. Do not include markdown. "
                    f"The JSON must validate against this schema named {schema_name}:\n"
                    f"{json.dumps(schema, separators=(',', ':'))}"
                ),
            },
            {
                "role": "user",
                "content": json.dumps(user_payload, default=str, separators=(",", ":")),
            },
        ]
        raw = await self._post(messages)
        return validate_agent_json(raw, output_model)

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type((httpx.HTTPError, httpx.TimeoutException)),
    )
    async def _post(self, messages: list[dict[str, str]]) -> str:
        headers = {
            "Authorization": f"Bearer {self.settings.groq_api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.settings.groq_model,
            "temperature": self.settings.groq_temperature,
            "max_tokens": self.settings.groq_max_tokens,
            "response_format": {"type": "json_object"},
            "messages": messages,
        }
        async with httpx.AsyncClient(timeout=self.settings.groq_timeout_seconds) as client:
            response = await client.post(str(self.settings.groq_base_url), headers=headers, json=body)
            response.raise_for_status()
            payload = response.json()
        return payload["choices"][0]["message"]["content"]
