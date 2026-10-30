import logging
import math
from typing import Literal

import httpx

from app.config import Settings

logger = logging.getLogger(__name__)

InputType = Literal["query", "passage"]
MAX_BATCH = 16
MAX_CHARS = 12_000  # bounded input; the model accepts far more, but alert text beyond this is noise and cost


class EmbeddingError(Exception):
    """An embedding call failed. Callers fall back to keyword + exact retrieval; they never invent vectors."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def normalise(vector: list[float], dims: int) -> list[float]:
    """Matryoshka truncation: keep the first `dims` values, then re-normalise to unit length."""
    cut = vector[:dims]
    norm = math.sqrt(sum(x * x for x in cut))
    if len(cut) < dims or norm == 0:
        raise EmbeddingError("BAD_EMBEDDING", "The embedding service returned an unusable vector.")
    return [x / norm for x in cut]


class EmbeddingClient:
    """Client for NVIDIA's OpenAI-compatible /v1/embeddings endpoint.

    Reference: https://docs.api.nvidia.com/nim/reference/nvidia-nemotron-3_5-embed-1b
    """

    def __init__(self, settings: Settings) -> None:
        self._key = settings.nvidia_api_key
        self._url = settings.nvidia_base_url.rstrip("/") + "/embeddings"
        self.model = settings.embedding_model
        self.dimensions = settings.embedding_dimensions
        self._timeout = settings.embedding_timeout_seconds
        self.calls = 0
        self.input_chars = 0

    @property
    def is_configured(self) -> bool:
        return bool(self._key and self._url and self.model)

    def embed(self, texts: list[str], input_type: InputType) -> list[list[float]]:
        if not self.is_configured:
            raise EmbeddingError("EMBEDDINGS_NOT_CONFIGURED", "Embeddings are not configured (NVIDIA_API_KEY).")
        out: list[list[float]] = []
        for start in range(0, len(texts), MAX_BATCH):
            out.extend(self._call([t[:MAX_CHARS] for t in texts[start:start + MAX_BATCH]], input_type))
        return out

    def _call(self, batch: list[str], input_type: InputType) -> list[list[float]]:
        body = {"model": self.model, "input": batch, "input_type": input_type, "encoding_format": "float", "truncate": "END"}
        self.calls += 1
        self.input_chars += sum(len(t) for t in batch)
        try:
            response = httpx.post(self._url, json=body, headers={"Authorization": f"Bearer {self._key}"}, timeout=self._timeout)
        except httpx.TimeoutException:
            raise EmbeddingError("EMBEDDINGS_TIMEOUT", "The embedding service timed out.")
        except httpx.HTTPError:
            raise EmbeddingError("EMBEDDINGS_UNAVAILABLE", "The embedding service could not be reached.")
        if response.status_code in (401, 403):
            raise EmbeddingError("EMBEDDINGS_AUTH", "The embedding service rejected the API key.")
        if response.status_code == 429:
            raise EmbeddingError("EMBEDDINGS_RATE_LIMITED", "The embedding service rate limit was reached.")
        if response.status_code >= 400:
            # Status only: the response body can echo the request, which contains alert text.
            logger.warning("Embedding request failed with HTTP %s", response.status_code)
            raise EmbeddingError("EMBEDDINGS_UNAVAILABLE", f"The embedding service returned HTTP {response.status_code}.")
        try:
            data = sorted(response.json()["data"], key=lambda d: d["index"])
            vectors = [normalise([float(x) for x in d["embedding"]], self.dimensions) for d in data]
        except EmbeddingError:
            raise
        except Exception:
            raise EmbeddingError("BAD_EMBEDDING", "The embedding service sent an unreadable response.")
        if len(vectors) != len(batch):
            raise EmbeddingError("BAD_EMBEDDING", "The embedding service returned the wrong number of vectors.")
        return vectors
