"""HTTP entry point: approval API, audit API, health, dev REST tool endpoint, and MCP.

The REST tool endpoint and the MCP tools call the SAME handle_tool_call().
"""
from contextlib import asynccontextmanager
from typing import Any, Literal
from uuid import UUID

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from . import approvals
from .auth import AuthError, Identity, authenticate
from .authorization import handle_tool_call
from .db import transaction
from .mcp_server import mcp, streamable_app
from .schemas import ApprovalDecision


@asynccontextmanager
async def lifespan(_app: FastAPI):
    async with mcp.session_manager.run():
        yield


app = FastAPI(title="AgentGate", version="0.1.0", lifespan=lifespan)


def current_identity(authorization: str | None = Header(default=None)) -> Identity:
    try:
        return authenticate(authorization)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail={"error": str(exc)},
                            headers={"WWW-Authenticate": "Bearer"}) from None


def _respond(outcome: approvals.Outcome) -> JSONResponse:
    return JSONResponse(jsonable_encoder(outcome.body), status_code=outcome.http_status)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/v1/tools/{tool_name}")
def call_tool(tool_name: str, arguments: dict[str, Any] = Body(...),
              identity: Identity = Depends(current_identity)) -> dict:
    """Development REST access to the same tools the MCP interface exposes."""
    return handle_tool_call(identity, tool_name, arguments)


@app.get("/v1/approvals")
def list_approvals(status: Literal["PENDING_APPROVAL", "APPROVED", "REJECTED", "EXPIRED"] = "PENDING_APPROVAL",
                   identity: Identity = Depends(current_identity)) -> JSONResponse:
    return _respond(approvals.list_for(identity, status))


@app.get("/v1/approvals/{approval_id}")
def get_approval(approval_id: UUID, identity: Identity = Depends(current_identity)) -> JSONResponse:
    return _respond(approvals.get_for(approval_id, identity))


@app.post("/v1/approvals/{approval_id}/approve")
def approve(approval_id: UUID, body: ApprovalDecision,
            identity: Identity = Depends(current_identity)) -> JSONResponse:
    return _respond(approvals.decide(approval_id, identity, "approve", body))


@app.post("/v1/approvals/{approval_id}/reject")
def reject(approval_id: UUID, body: ApprovalDecision,
           identity: Identity = Depends(current_identity)) -> JSONResponse:
    return _respond(approvals.decide(approval_id, identity, "reject", body))


@app.get("/v1/audit")
def audit_events(request_id: UUID = Query(...), identity: Identity = Depends(current_identity)) -> JSONResponse:
    """Approvers can read audit events for their own tenant only."""
    if identity.kind != "human" or "approver" not in identity.roles:
        return JSONResponse({"error": "not_permitted"}, status_code=403)
    with transaction() as conn:
        rows = conn.execute(
            "SELECT event_id, request_id, actor, event_type, policy_version, details, created_at "
            "FROM audit_events WHERE request_id = %s AND tenant_id = %s ORDER BY id",
            (request_id, identity.tenant_id),
        ).fetchall()
    return JSONResponse(jsonable_encoder(rows))


class RequireBearer:
    """Cheap outer check: no bearer header, no MCP processing. Each tool call
    still fully validates the token itself."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            if not headers.get(b"authorization", b"").decode().lower().startswith("bearer "):
                response = JSONResponse({"error": "missing_bearer_token"}, status_code=401,
                                        headers={"WWW-Authenticate": "Bearer"})
                await response(scope, receive, send)
                return
        await self.inner(scope, receive, send)


# Mounted last so the FastAPI routes above take precedence. MCP lives at /mcp.
app.mount("/", RequireBearer(streamable_app))
