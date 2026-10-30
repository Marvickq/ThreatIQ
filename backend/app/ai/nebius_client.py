import logging
from dataclasses import dataclass

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)


class ModelError(Exception):
    """A model call failed. `code` maps onto the API error codes in TechSpec.md."""

    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class ModelResponse:
    content: str
    model: str


class NebiusClient:
    """Thin client for Nebius Token Factory's OpenAI-compatible chat completions API.

    Endpoint, auth and `response_format` usage follow
    https://docs.tokenfactory.nebius.com/api-reference/introduction and
    https://docs.tokenfactory.nebius.com/ai-models-inference/json
    """

    def __init__(self, settings: Settings) -> None:
        self._api_key = settings.nebius_api_key
        self._base_url = settings.nebius_base_url.rstrip("/")
        self._model = settings.nebius_model
        self._timeout = settings.nebius_timeout_seconds
        self._max_tokens = settings.nebius_max_tokens

    def params(self) -> dict:
        """Inference settings recorded with every assessment."""
        return {"temperature": 0.2, "max_tokens": self._max_tokens, "response_format": "json_schema", "timeout_seconds": self._timeout}

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key and self._base_url and self._model)

    def complete_json(self, system: str, user: str, schema_name: str, schema: dict) -> ModelResponse:
        if not self.is_configured:
            raise ModelError(
                "MODEL_NOT_CONFIGURED",
                "The AI model is not configured. Set the NEBIUS_* values in backend/.env.local.",
                503,
            )

        body = {
            "model": self._model,
            "temperature": 0.2,
            # Reasoning tokens count toward this limit, so keep it generous.
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "schema": schema, "strict": True},
            },
        }

        try:
            response = httpx.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json=body,
                timeout=self._timeout,
            )
        except httpx.TimeoutException:
            logger.warning("Model request timed out after %ss", self._timeout)
            raise ModelError("MODEL_UNAVAILABLE", "The assessment service timed out. Please retry.", 502)
        except httpx.HTTPError as exc:
            logger.warning("Model request failed: %s", type(exc).__name__)
            raise ModelError("MODEL_UNAVAILABLE", "The assessment service is temporarily unavailable.", 502)

        if response.status_code != 200:
            # Log the status only; response bodies may echo request content.
            logger.warning("Model provider returned HTTP %s", response.status_code)
            if response.status_code in (401, 403):
                message = "The assessment service rejected the configured credentials."
            elif response.status_code == 429:
                message = "The assessment service is rate limited. Please retry shortly."
            else:
                message = "The assessment service is temporarily unavailable."
            raise ModelError("MODEL_UNAVAILABLE", message, 502)

        try:
            payload = response.json()
            choice = payload["choices"][0]
            message_obj = choice["message"]
            content = message_obj.get("content") or ""
            finish_reason = choice.get("finish_reason")
            model = payload.get("model") or self._model
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise ModelError("INVALID_MODEL_OUTPUT", "The model returned an unreadable response.", 502)

        if message_obj.get("refusal"):
            raise ModelError("INVALID_MODEL_OUTPUT", "The model declined to produce an assessment.", 502)
        if finish_reason == "length":
            # The reasoning model spent its whole output budget. Retrying would just repeat this.
            raise ModelError(
                "MODEL_OUTPUT_TRUNCATED",
                "The model ran out of output budget before finishing. An administrator can raise NEBIUS_MAX_TOKENS.",
                502,
            )
        if not content.strip():
            raise ModelError("INVALID_MODEL_OUTPUT", "The model returned an empty response.", 502)

        return ModelResponse(content=content, model=model)
