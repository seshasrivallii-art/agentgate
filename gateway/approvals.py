"""Durable, action-specific approvals.

An approval is bound to an immutable canonical action. The approver must
echo back the digest of the exact action they reviewed.
"""
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from typing import Literal

import psycopg
from psycopg.types.json import Jsonb

from . import audit
from .auth import Identity
from .config import settings
from .db import transaction
from .policy_client import PolicyClient, build_input, get_policy_client
from .schemas import ApprovalDecision

ACTION_SCHEMA_VERSION = "agentgate.action/v1"
GENERIC = {"error": "not_found_or_not_permitted"}


def canonical_action(*, agent_id: str, tenant_id: str, tool: str, arguments: dict, resource_ids: list[str]) -> dict:
    return {
        "schema_version": ACTION_SCHEMA_VERSION,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "tool": tool,
        "arguments": arguments,
        "resources": sorted(resource_ids),
    }


def action_digest(action: dict) -> str:
    canonical = json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_pending(conn: psycopg.Connection, *, request_id: uuid.UUID, tenant_id: str, requested_by: str,
                   tool: str, action: dict, policy_reason: str) -> dict:
    return conn.execute(
        """
        INSERT INTO approvals (request_id, tenant_id, requested_by, tool, action_snapshot,
                               action_digest, policy_reason, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, now() + %s * interval '1 second')
        RETURNING id, action_digest, expires_at
        """,
        (request_id, tenant_id, requested_by, tool, Jsonb(action), action_digest(action),
         policy_reason, settings.approval_ttl_seconds),
    ).fetchone()


def approval_resource(row: dict) -> dict:
    return {"id": row["id"], "type": "approval", "tenant_id": row["tenant_id"],
            "requested_by": row["requested_by"], "tool": row["tool"]}


@dataclass
class Outcome:
    http_status: int
    body: dict | list


def _view(row: dict, execution: dict | None) -> dict:
    """What the human sees: agent, tenant, tool, exact payload, expiry, reason."""
    return {
        "id": str(row["id"]),
        "request_id": str(row["request_id"]),
        "status": row["status"],
        "tenant_id": row["tenant_id"],
        "requested_by": row["requested_by"],
        "tool": row["tool"],
        "action": row["action_snapshot"],
        "action_digest": row["action_digest"],
        "policy_reason": row["policy_reason"],
        "created_at": row["created_at"].isoformat(),
        "expires_at": row["expires_at"].isoformat(),
        "approver": row["approver"],
        "execution": None if execution is None else {
            "id": str(execution["id"]), "status": execution["status"],
            "error": execution["error"], "result": execution["result"],
        },
    }


def _may_decide(conn, policy: PolicyClient, approver: Identity, row: dict, purpose: str = "decide") -> bool:
    result = policy.evaluate(build_input(approver, "approvals.decide", approval_resource(row), row["request_id"]))
    audit.record(conn, "policy.evaluated", actor=approver.actor, request_id=row["request_id"],
                 tenant_id=row["tenant_id"], policy_version=result.policy_version,
                 details={"action": "approvals.decide", "purpose": purpose, "approval_id": str(row["id"]),
                          "decision": result.decision, "reasons": result.reasons})
    return result.decision == "allow"


def _execution_for(conn, approval_id) -> dict | None:
    return conn.execute("SELECT id, status, error, result FROM executions WHERE approval_id = %s",
                        (approval_id,)).fetchone()


def list_for(approver: Identity, status: str, *, policy: PolicyClient | None = None) -> Outcome:
    policy = policy or get_policy_client()
    with transaction() as conn:
        rows = conn.execute(
            "SELECT * FROM approvals WHERE tenant_id = %s AND status = %s ORDER BY created_at DESC LIMIT 100",
            (approver.tenant_id, status),
        ).fetchall()
        visible = [_view(r, _execution_for(conn, r["id"])) for r in rows if _may_decide(conn, policy, approver, r, purpose="view")]
    return Outcome(200, visible)


def get_for(approval_id: uuid.UUID, approver: Identity, *, policy: PolicyClient | None = None) -> Outcome:
    policy = policy or get_policy_client()
    with transaction() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = %s", (approval_id,)).fetchone()
        if row is None or not _may_decide(conn, policy, approver, row, purpose="view"):
            return Outcome(403, GENERIC)
        return Outcome(200, _view(row, _execution_for(conn, row["id"])))


def decide(approval_id: uuid.UUID, approver: Identity, decision: Literal["approve", "reject"],
           body: ApprovalDecision, *, policy: PolicyClient | None = None) -> Outcome:
    policy = policy or get_policy_client()
    actor = approver.actor
    with transaction() as conn:
        row = conn.execute(
            "SELECT *, (now() >= expires_at) AS is_expired FROM approvals WHERE id = %s FOR UPDATE",
            (approval_id,),
        ).fetchone()
        if row is None:
            audit.record(conn, "approval.denied", actor=actor, tenant_id=approver.tenant_id,
                         details={"approval_id": str(approval_id), "reason": "not_found"})
            return Outcome(403, GENERIC)

        def log(event: str, **details):
            audit.record(conn, event, actor=actor, request_id=row["request_id"], tenant_id=row["tenant_id"],
                         details={"approval_id": str(row["id"]), **details})

        # 1. Is this human allowed to decide this approval? (agents, other tenants, self-approval -> no)
        if not _may_decide(conn, policy, approver, row):
            log("approval.denied", reason="approver_not_authorized")
            return Outcome(403, GENERIC)

        # 2. Replay protection: only PENDING approvals can be decided, exactly once.
        if row["status"] != "PENDING_APPROVAL":
            log("approval.replay_rejected", current_status=row["status"])
            return Outcome(409, {"error": "approval_not_pending", "status": row["status"]})

        # 3. Expiry.
        if row["is_expired"]:
            conn.execute("UPDATE approvals SET status = 'EXPIRED' WHERE id = %s", (row["id"],))
            log("approval.expired")
            return Outcome(410, {"error": "approval_expired"})

        # 4. The approver must confirm the exact action they reviewed.
        if not hmac.compare_digest(body.action_digest, row["action_digest"]):
            log("approval.digest_mismatch")
            return Outcome(409, {"error": "action_digest_mismatch"})

        # 5. The stored snapshot must still match its digest.
        if action_digest(row["action_snapshot"]) != row["action_digest"]:
            log("approval.integrity_failure")
            return Outcome(409, {"error": "stored_action_integrity_failure"})

        if decision == "reject":
            conn.execute(
                "UPDATE approvals SET status = 'REJECTED', approver = %s, decided_at = now(), "
                "decision_comment = %s WHERE id = %s",
                (approver.principal_id, body.comment, row["id"]),
            )
            log("approval.rejected")
            return Outcome(200, {"id": str(row["id"]), "status": "REJECTED"})

        conn.execute(
            "UPDATE approvals SET status = 'APPROVED', approver = %s, decided_at = now(), "
            "decision_comment = %s WHERE id = %s",
            (approver.principal_id, body.comment, row["id"]),
        )
        execution = conn.execute(
            "INSERT INTO executions (approval_id, request_id, idempotency_key) VALUES (%s, %s, %s) RETURNING id",
            (row["id"], row["request_id"], f"tickets.create:{row['request_id']}"),
        ).fetchone()
        log("approval.granted", execution_id=str(execution["id"]))
        return Outcome(200, {"id": str(row["id"]), "status": "APPROVED",
                             "execution": {"id": str(execution["id"]), "status": "QUEUED"}})


def expire_stale() -> int:
    with transaction() as conn:
        rows = conn.execute(
            "UPDATE approvals SET status = 'EXPIRED' WHERE status = 'PENDING_APPROVAL' AND expires_at < now() "
            "RETURNING id, request_id, tenant_id"
        ).fetchall()
        for r in rows:
            audit.record(conn, "approval.expired", actor="system:worker", request_id=r["request_id"],
                         tenant_id=r["tenant_id"], details={"approval_id": str(r["id"])})
    return len(rows)
