from __future__ import annotations

import json
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

ModelT = TypeVar("ModelT", bound=BaseModel)


class StrictJsonError(ValueError):
    """Raised when an agent response is not valid strict JSON for its contract."""


def extract_json_object(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < start:
            raise StrictJsonError("No JSON object found in response") from None
        parsed = json.loads(text[start : end + 1])
    if not isinstance(parsed, dict):
        raise StrictJsonError("Agent response must be a JSON object")
    return parsed


def validate_agent_json(raw: str, model: type[ModelT]) -> ModelT:
    parsed = extract_json_object(raw)
    try:
        return model.model_validate(parsed)
    except ValidationError as exc:
        raise StrictJsonError(str(exc)) from exc
