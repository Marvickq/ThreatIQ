"""Artifact storage for large evidence/raw events.

Metadata and a SHA-256 hash always stay in PostgreSQL. When S3 is configured, large bodies are
stored there (server-side encrypted); otherwise they stay inline in the database. The S3 path is
implemented against the standard boto3 API but has NOT been exercised against a real bucket in
this repository's verification.
"""
import hashlib
import json
import logging

from app.config import get_settings

logger = logging.getLogger(__name__)


def _client():
    import boto3

    settings = get_settings()
    kwargs = {}
    if settings.s3_region:
        kwargs["region_name"] = settings.s3_region
    if settings.s3_endpoint_url:
        kwargs["endpoint_url"] = settings.s3_endpoint_url
    # Credentials come from the standard AWS chain (task role, env, profile); none are hardcoded.
    return boto3.client("s3", **kwargs)


def enabled() -> bool:
    return bool(get_settings().s3_bucket)


def sha256_json(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def put_if_large(organization_id: str, kind: str, data: dict) -> str | None:
    """Store `data` in S3 if configured and larger than the inline limit. Returns the s3:// URI or None."""
    settings = get_settings()
    body = json.dumps(data, default=str).encode("utf-8")
    if not enabled() or len(body) <= settings.artifact_inline_max_bytes:
        return None
    digest = hashlib.sha256(body).hexdigest()
    key = f"{settings.s3_prefix}{organization_id}/{kind}/{digest}.json"
    try:  # pragma: no cover - requires AWS
        _client().put_object(
            Bucket=settings.s3_bucket, Key=key, Body=body, ContentType="application/json", ServerSideEncryption="AES256"
        )
    except Exception as exc:
        logger.warning("S3 upload failed (%s); keeping the artifact inline", type(exc).__name__)
        return None
    return f"s3://{settings.s3_bucket}/{key}"


def get(uri: str) -> dict | None:  # pragma: no cover - requires AWS
    settings = get_settings()
    prefix = f"s3://{settings.s3_bucket}/"
    if not uri.startswith(prefix):
        return None
    try:
        obj = _client().get_object(Bucket=settings.s3_bucket, Key=uri[len(prefix):])
        return json.loads(obj["Body"].read())
    except Exception as exc:
        logger.warning("S3 download failed (%s)", type(exc).__name__)
        return None
