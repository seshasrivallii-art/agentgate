"""Layer A as pytest: constructed requests straight at the authenticated gateway."""
import httpx
import pytest

from agent.auth_client import agent_token, bearer, human_token
from tests.helpers import GATEWAY, decide, propose_ticket, tool, view

pytestmark = pytest.mark.stack


@pytest.fixture(scope="module")
def support():
    return agent_token("support-agent")


def test_same_tenant_lookup_allowed_with_safe_fields(support):
    r = tool("customers.lookup", {"customer_id": "customer-104"}, support).json()
    assert r["status"] == "ok"
    assert set(r["data"]) == {"customer_id", "display_name", "support_plan", "open_ticket_count"}
    assert "CANARY" not in str(r)


def test_cross_tenant_lookup_denied(support):
    r = tool("customers.lookup", {"customer_id": "customer-999"}, support).json()
    assert r["status"] == "denied" and "CANARY" not in str(r)


def test_missing_and_forbidden_look_identical(support):
    missing = tool("customers.lookup", {"customer_id": "customer-000"}, support).json()
    forbidden = tool("customers.lookup", {"customer_id": "customer-999"}, support).json()
    assert missing["status"] == forbidden["status"] == "denied"
    assert missing["reason"] == forbidden["reason"]


def test_search_never_returns_restricted_or_other_tenant(support):
    for q in ["vpn", "incident", "budget", "CANARY"]:
        r = tool("documents.search", {"query": q, "limit": 10}, support).json()
        assert r["status"] == "ok"
        assert all(d["classification"] in {"public", "internal"} for d in r["data"]["documents"])
        assert "CANARY" not in str(r)


def test_finance_agent_cannot_lookup_or_create(support):
    finance = agent_token("finance-agent")
    assert tool("customers.lookup", {"customer_id": "customer-104"}, finance).json()["status"] == "denied"
    r = tool("tickets.create", {"customer_id": "customer-104", "title": "x y z", "description": "d"}, finance).json()
    assert r["status"] == "denied"


def test_model_supplied_privileges_rejected(support):
    r = tool("customers.lookup", {"customer_id": "customer-999", "role": "admin",
                                  "tenant_id": "tenant-b", "approved": True}, support).json()
    assert r["status"] == "invalid"


def test_unknown_tool_rejected(support):
    assert tool("customers.delete", {"customer_id": "customer-104"}, support).json()["status"] == "invalid"


def test_wrong_audience_token_rejected():
    r = tool("customers.lookup", {"customer_id": "customer-104"}, agent_token("other-service"))
    assert r.status_code == 401


def test_no_token_and_garbage_token_rejected():
    assert httpx.post(f"{GATEWAY}/v1/tools/customers.lookup", json={"customer_id": "customer-104"}).status_code == 401
    assert tool("customers.lookup", {"customer_id": "customer-104"}, "not.a.jwt").status_code == 401


def test_mcp_endpoint_requires_token():
    r = httpx.post(f"{GATEWAY}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401


def test_proposal_does_not_create_ticket():
    p = propose_ticket("no-approval")
    v = view(p["approval_id"]).json()
    assert v["status"] == "PENDING_APPROVAL" and v["execution"] is None


def test_agent_cannot_approve_its_own_request(support):
    p = propose_ticket("self-approve")
    digest = view(p["approval_id"]).json()["action_digest"]
    assert decide(p["approval_id"], digest, support).status_code in (401, 403)


def test_other_tenant_approver_denied():
    p = propose_ticket("cross-tenant-approver")
    digest = view(p["approval_id"]).json()["action_digest"]
    assert decide(p["approval_id"], digest, human_token("bob")).status_code == 403
    assert view(p["approval_id"], user="bob").status_code == 403


def test_wrong_digest_rejected_and_approval_stays_pending():
    p = propose_ticket("digest")
    r = decide(p["approval_id"], "0" * 64, human_token("alice"))
    assert r.status_code == 409
    assert view(p["approval_id"]).json()["status"] == "PENDING_APPROVAL"


def test_tools_reject_human_tokens():
    r = tool("customers.lookup", {"customer_id": "customer-104"}, human_token("alice")).json()
    assert r["status"] == "denied"


def test_audit_trail_recorded(support):
    r = tool("customers.lookup", {"customer_id": "customer-999"}, support).json()
    events = httpx.get(f"{GATEWAY}/v1/audit", params={"request_id": r["request_id"]},
                       headers=bearer(human_token("alice"))).json()
    types = [e["event_type"] for e in events]
    assert {"tool.requested", "identity.validated", "policy.evaluated", "policy.denied"} <= set(types)
    assert all(e["policy_version"] for e in events if e["event_type"].startswith("policy."))
    assert "Bearer" not in str(events)
