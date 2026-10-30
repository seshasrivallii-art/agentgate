"""Token validation and trusted identity resolution.

Identity comes from (1) a signature-verified, audience-bound token and
(2) the server-side registry. Tool arguments and MCP session IDs never
establish identity.
"""
from dataclasses import dataclass
from typing import Callable, Literal

import jwt
import psycopg
from jwt import PyJWKClient

from . import audit
from .config import settings
from .db import transaction


class AuthError(Exception):
    """Raised for any authentication failure. The message is a short reason code."""


@dataclass(frozen=True)
class Identity:
    kind: Literal["agent", "human"]
    principal_id: str
    tenant_id: str
    roles: tuple[str, ...]

    @property
    def actor(self) -> str:
        return f"{self.kind}:{self.principal_id}"

    def opa_subject(self) -> dict:
        return {"type": self.kind, "id": self.principal_id,
                "tenant_id": self.tenant_id, "roles": list(self.roles)}


_jwks: PyJWKClient | None = None


def _default_key_resolver(token: str):
    global _jwks
    if _jwks is None:
        _jwks = PyJWKClient(settings.oidc_jwks_url, cache_keys=True, lifespan=300)
    return _jwks.get_signing_key_from_jwt(token).key


def verify_jwt(
    token: str | None,
    *,
    key_resolver: Callable[[str], object] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> dict:
    """Verify signature, algorithm, issuer, audience, and expiry."""
    if not token:
        raise AuthError("missing_token")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256":
            raise AuthError("unsupported_algorithm")
        key = (key_resolver or _default_key_resolver)(token)
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=audience or settings.token_audience,
            issuer=issuer or settings.oidc_issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
            leeway=10,
        )
    except AuthError:
        raise
    except jwt.ExpiredSignatureError:
        raise AuthError("token_expired") from None
    except jwt.InvalidAudienceError:
        raise AuthError("invalid_audience") from None
    except jwt.InvalidIssuerError:
        raise AuthError("invalid_issuer") from None
    except jwt.MissingRequiredClaimError as exc:
        raise AuthError(f"missing_claim:{exc.claim}") from None
    except Exception:  # bad signature, malformed token, JWKS fetch failure...
        raise AuthError("invalid_token") from None


def load_agent_identity(conn: psycopg.Connection, client_id: str) -> Identity | None:
    row = conn.execute(
        "SELECT client_id, tenant_id, roles FROM agent_registry WHERE client_id = %s AND active",
        (client_id,),
    ).fetchone()
    return Identity("agent", row["client_id"], row["tenant_id"], tuple(row["roles"])) if row else None


def load_human_identity(conn: psycopg.Connection, username: str) -> Identity | None:
    row = conn.execute(
        "SELECT username, tenant_id, roles FROM approvers WHERE username = %s AND active",
        (username,),
    ).fetchone()
    return Identity("human", row["username"], row["tenant_id"], tuple(row["roles"])) if row else None


def resolve_identity(conn: psycopg.Connection, claims: dict) -> Identity:
    username = str(claims.get("preferred_username", ""))
    azp = claims.get("azp")
    is_service_account = username.startswith("service-account-") or "client_id" in claims

    if is_service_account:
        client_id = claims.get("client_id") or azp
        if not client_id or azp != client_id or username != f"service-account-{client_id}".lower():
            raise AuthError("inconsistent_service_account_claims")
        identity = load_agent_identity(conn, client_id)
        if identity is None:
            raise AuthError("unregistered_agent")
        return identity

    if azp not in settings.human_clients:
        raise AuthError("client_not_allowed_for_humans")
    identity = load_human_identity(conn, username)
    if identity is None:
        raise AuthError("unknown_human")
    return identity


def _bearer(header: str | None) -> str | None:
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def authenticate(authorization_header: str | None) -> Identity:
    try:
        claims = verify_jwt(_bearer(authorization_header))
        with transaction() as conn:
            return resolve_identity(conn, claims)
    except AuthError as exc:
        _audit_rejection(str(exc))
        raise


def _audit_rejection(reason: str) -> None:
    try:
        with transaction() as conn:
            audit.record(conn, "identity.rejected", actor="unauthenticated", details={"reason": reason})
    except Exception:
        pass  # Never let audit failure turn a rejection into an acceptance.
