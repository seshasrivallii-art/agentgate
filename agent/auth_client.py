"""Token helpers for the agent runner, approver CLI, evals, and tests (dev credentials only)."""
import os

import httpx

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "agentgate")
TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"


def _secret(client_id: str) -> str:
    env = client_id.upper().replace("-", "_") + "_SECRET"
    return os.environ.get(env, f"{client_id}-dev-secret")


def agent_token(client_id: str = "support-agent") -> str:
    """Client-credentials token for a service-account agent."""
    response = httpx.post(TOKEN_URL, timeout=10, data={
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": _secret(client_id),
    })
    response.raise_for_status()
    return response.json()["access_token"]


def human_token(username: str, password: str | None = None) -> str:
    """Password-grant token for a human approver (dev only; use a browser flow in production)."""
    password = password or os.environ.get(f"{username.upper()}_PASSWORD", f"{username}-dev-password")
    response = httpx.post(TOKEN_URL, timeout=10, data={
        "grant_type": "password", "client_id": "approval-cli", "username": username,
        "password": password, "scope": "openid",
    })
    response.raise_for_status()
    return response.json()["access_token"]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
