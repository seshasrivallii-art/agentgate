"""MCP interface: exactly three tools. Every call is re-authenticated from the
request's bearer token (an MCP session is not identity) and routed through
handle_tool_call()."""
import functools
from typing import Any

import anyio
from mcp.server.fastmcp import Context, FastMCP

from .auth import AuthError, authenticate
from .authorization import handle_tool_call
from .config import settings


def _make_server() -> FastMCP:
    kwargs: dict[str, Any] = {
        "name": "AgentGate",
        "instructions": "Enterprise support tools. All calls are authorized by the gateway, not by the model.",
        "stateless_http": True,
        "json_response": True,
    }
    try:  # DNS-rebinding protection (available in recent MCP SDK versions)
        from mcp.server.transport_security import TransportSecuritySettings
        kwargs["transport_security"] = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(settings.mcp_allowed_hosts),
            allowed_origins=[f"http://{h}" for h in settings.mcp_allowed_hosts],
        )
    except ImportError:
        pass
    return FastMCP(**kwargs)


mcp = _make_server()


def _authorization_header(ctx: Context) -> str | None:
    request = getattr(ctx.request_context, "request", None)
    return request.headers.get("authorization") if request is not None else None


async def _dispatch(ctx: Context, tool: str, arguments: dict) -> dict:
    header = _authorization_header(ctx)
    try:
        identity = await anyio.to_thread.run_sync(authenticate, header)
    except AuthError as exc:
        return {"status": "unauthenticated", "error": str(exc)}
    return await anyio.to_thread.run_sync(functools.partial(handle_tool_call, identity, tool, arguments))


@mcp.tool(name="documents.search",
          description="Search internal support documents you are permitted to read. Returns at most 10 results.")
async def documents_search(ctx: Context, query: str, limit: int = 5) -> dict[str, Any]:
    return await _dispatch(ctx, "documents.search", {"query": query, "limit": limit})


@mcp.tool(name="customers.lookup",
          description="Look up support-safe fields for one customer by id, e.g. customer-104.")
async def customers_lookup(ctx: Context, customer_id: str) -> dict[str, Any]:
    return await _dispatch(ctx, "customers.lookup", {"customer_id": customer_id})


@mcp.tool(name="tickets.create",
          description=("Propose a support ticket. It is NOT created immediately: a human approver must "
                       "approve the exact ticket. priority is one of low, normal, high."))
async def tickets_create(ctx: Context, customer_id: str, title: str, description: str,
                         priority: str = "normal") -> dict[str, Any]:
    return await _dispatch(ctx, "tickets.create", {"customer_id": customer_id, "title": title,
                                                   "description": description, "priority": priority})


streamable_app = mcp.streamable_http_app()   # serves POST /mcp
