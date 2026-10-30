import os
import uuid

import httpx

from agent.auth_client import agent_token, bearer, human_token

GATEWAY = os.environ.get("GATEWAY_URL", "http://localhost:8000")


def tool(name: str, args: dict, token: str) -> httpx.Response:
    return httpx.post(f"{GATEWAY}/v1/tools/{name}", json=args, headers=bearer(token), timeout=15)


def propose_ticket(title_prefix: str = "test") -> dict:
    body = tool("tickets.create", {
        "customer_id": "customer-104",
        "title": f"{title_prefix} {uuid.uuid4().hex[:8]}",
        "description": "Customer cannot connect after a client update.",
        "priority": "normal",
    }, agent_token("support-agent")).json()
    assert body["status"] == "approval_required", body
    return body


def view(approval_id: str, user: str = "alice") -> httpx.Response:
    return httpx.get(f"{GATEWAY}/v1/approvals/{approval_id}", headers=bearer(human_token(user)), timeout=15)


def decide(approval_id: str, digest: str, token: str, action: str = "approve") -> httpx.Response:
    return httpx.post(f"{GATEWAY}/v1/approvals/{approval_id}/{action}",
                      json={"action_digest": digest}, headers=bearer(token), timeout=15)
