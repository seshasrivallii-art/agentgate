import os
from dataclasses import dataclass, field


def _csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(v.strip() for v in os.environ.get(name, default).split(",") if v.strip())


@dataclass(frozen=True)
class Settings:
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql://agentgate_app:change-me-app@localhost:5432/agentgate"
    )
    opa_url: str = os.environ.get("OPA_URL", "http://localhost:8181")
    opa_timeout_seconds: float = float(os.environ.get("OPA_TIMEOUT_SECONDS", "2"))
    oidc_issuer: str = os.environ.get("OIDC_ISSUER", "http://localhost:8080/realms/agentgate")
    oidc_jwks_url: str = os.environ.get(
        "OIDC_JWKS_URL", "http://localhost:8080/realms/agentgate/protocol/openid-connect/certs"
    )
    token_audience: str = os.environ.get("TOKEN_AUDIENCE", "agentgate")
    # Keycloak clients that humans may log in through. Agents never get these.
    human_clients: tuple[str, ...] = field(default_factory=lambda: _csv("HUMAN_CLIENTS", "approval-cli"))
    approval_ttl_seconds: int = int(os.environ.get("APPROVAL_TTL_SECONDS", "900"))
    mcp_allowed_hosts: tuple[str, ...] = field(
        default_factory=lambda: _csv("MCP_ALLOWED_HOSTS", "localhost:8000,127.0.0.1:8000,gateway:8000")
    )


settings = Settings()
