"""Append-only audit events. Never log bearer tokens, secrets, or unrestricted content."""
import hashlib
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

_SECRET_KEYS = {"authorization", "access_token", "token", "client_secret", "password", "secret"}
_CONTENT_KEYS = {"body", "description", "excerpt", "internal_notes", "billing_email"}
_MAX_STR = 200


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in _SECRET_KEYS:
                out[key] = "[REDACTED]"
            elif lowered in _CONTENT_KEYS and isinstance(item, str):
                out[key] = {
                    "redacted": True,
                    "length": len(item),
                    "sha256_prefix": hashlib.sha256(item.encode()).hexdigest()[:16],
                }
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value[:50]]
    if isinstance(value, str):
        return value if len(value) <= _MAX_STR else value[:_MAX_STR] + "..."
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def record(
    conn: psycopg.Connection,
    event_type: str,
    *,
    actor: str,
    request_id=None,
    tenant_id: str | None = None,
    policy_version: str | None = None,
    details: dict | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO audit_events (request_id, tenant_id, actor, event_type, policy_version, details)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (request_id, tenant_id, actor, event_type, policy_version, Jsonb(redact(details or {}))),
    )
