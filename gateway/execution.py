"""Execution worker: runs ONLY stored, approved actions.

Claim, recheck, insert the ticket, mark success, and audit all happen in one
PostgreSQL transaction. A crash anywhere rolls everything back and leaves the
execution QUEUED; tickets.request_id is UNIQUE, so retries never duplicate.
"""
import logging
import os
import signal
import time
import uuid
from typing import Callable

import psycopg
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from . import approvals, audit
from .auth import load_agent_identity, load_human_identity
from .db import transaction
from .policy_client import PolicyClient, build_input, get_policy_client
from .schemas import TicketCreateArgs
from .tools import customers, tickets

log = logging.getLogger("agentgate.worker")


class _RetryLater(Exception):
    """Transient condition (e.g. OPA down). Roll back and keep the execution QUEUED."""


def _claim(conn: psycopg.Connection, only_execution_id: uuid.UUID | None) -> dict | None:
    return conn.execute(
        """
        SELECT e.id, e.approval_id, e.request_id,
               a.action_snapshot, a.action_digest, a.status AS approval_status, a.approver,
               a.tenant_id, a.requested_by, a.tool,
               (a.decided_at IS NOT NULL AND a.decided_at <= a.expires_at) AS approved_in_time
        FROM executions e
        JOIN approvals a ON a.id = e.approval_id
        WHERE e.status = 'QUEUED'
          AND (%(only)s::uuid IS NULL OR e.id = %(only)s::uuid)
        ORDER BY e.created_at
        LIMIT 1
        FOR UPDATE OF e SKIP LOCKED
        """,
        {"only": only_execution_id},
    ).fetchone()


def _recheck(conn: psycopg.Connection, row: dict, policy: PolicyClient) -> tuple[str | None, TicketCreateArgs | None]:
    """Re-verify everything at execution time. Returns (failure_reason, args)."""
    snapshot = row["action_snapshot"]

    if row["approval_status"] != "APPROVED" or not row["approved_in_time"]:
        return "approval_not_valid", None
    if approvals.action_digest(snapshot) != row["action_digest"]:
        return "action_digest_mismatch", None
    if (snapshot.get("schema_version") != approvals.ACTION_SCHEMA_VERSION
            or snapshot.get("tool") != "tickets.create" or row["tool"] != "tickets.create"
            or snapshot.get("tenant_id") != row["tenant_id"]
            or snapshot.get("agent_id") != row["requested_by"]):
        return "snapshot_binding_mismatch", None
    try:
        args = TicketCreateArgs.model_validate(snapshot["arguments"])
    except (ValidationError, KeyError, TypeError):
        return "stored_payload_invalid", None

    approver = load_human_identity(conn, row["approver"] or "")
    if approver is None:
        return "approver_no_longer_active", None
    approval_resource = approvals.approval_resource({**row, "id": row["approval_id"]})
    result = policy.evaluate(build_input(approver, "approvals.decide", approval_resource, row["request_id"]))
    if not result.available:
        raise _RetryLater(result.reasons[0] if result.reasons else "policy_unavailable")
    if result.decision != "allow":
        return "approver_no_longer_authorized", None

    agent = load_agent_identity(conn, row["requested_by"])
    if agent is None:
        return "agent_no_longer_active", None
    meta = customers.get_metadata(conn, args.customer_id)
    if meta is None:
        return "customer_missing", None
    result = policy.evaluate(build_input(agent, "tickets.create", meta, row["request_id"]))
    if not result.available:
        raise _RetryLater(result.reasons[0] if result.reasons else "policy_unavailable")
    if result.decision == "deny":
        return "agent_no_longer_authorized", None
    return None, args


def process_one(*, policy: PolicyClient | None = None, only_execution_id: uuid.UUID | str | None = None,
                crash_hook: Callable[[], None] | None = None) -> dict | None:
    """Process at most one QUEUED execution. Returns None when there is nothing to do.

    crash_hook is for recovery tests: it runs after the ticket insert and before commit.
    """
    policy = policy or get_policy_client()
    only = uuid.UUID(str(only_execution_id)) if only_execution_id else None
    claimed_id = None
    try:
        with transaction() as conn:
            row = _claim(conn, only)
            if row is None:
                return None
            claimed_id = row["id"]

            def log_event(event: str, **details):
                audit.record(conn, event, actor="system:worker", request_id=row["request_id"],
                             tenant_id=row["tenant_id"],
                             details={"execution_id": str(row["id"]), "approval_id": str(row["approval_id"]), **details})

            conn.execute("UPDATE executions SET status = 'EXECUTING', started_at = now(), "
                         "attempts = attempts + 1 WHERE id = %s", (row["id"],))
            log_event("execution.started")

            reason, args = _recheck(conn, row, policy)
            if reason:
                conn.execute("UPDATE executions SET status = 'FAILED', error = %s, finished_at = now() "
                             "WHERE id = %s", (reason, row["id"]))
                log_event("execution.failed", reason=reason)
                return {"status": "FAILED", "execution_id": str(row["id"]), "reason": reason}

            # Execute the STORED payload, never new model arguments.
            ticket_id = tickets.insert_ticket(conn, tenant_id=row["tenant_id"], request_id=row["request_id"], args=args)
            if crash_hook is not None:
                crash_hook()
            replayed = ticket_id is None
            if replayed:
                ticket_id = tickets.find_by_request(conn, row["request_id"])

            conn.execute("UPDATE executions SET status = 'SUCCEEDED', finished_at = now(), result = %s "
                         "WHERE id = %s", (Jsonb({"ticket_id": str(ticket_id)}), row["id"]))
            log_event("execution.succeeded", ticket_id=str(ticket_id), idempotent_replay=replayed)
            return {"status": "SUCCEEDED", "execution_id": str(row["id"]), "ticket_id": str(ticket_id)}
    except _RetryLater as exc:
        log.warning("execution %s deferred: %s", claimed_id, exc)
        return {"status": "RETRY", "execution_id": str(claimed_id), "reason": str(exc)}


_stop = False


def _handle_stop(signum, frame):
    global _stop
    _stop = True


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    poll = float(os.environ.get("WORKER_POLL_SECONDS", "1"))
    log.info("worker started")
    while not _stop:
        result = None
        try:
            approvals.expire_stale()
            result = process_one()
            if result:
                log.info("execution result: %s", result)
        except Exception:
            log.exception("worker iteration failed")
        if result is None or result.get("status") == "RETRY":
            time.sleep(poll)
    log.info("worker stopped")


if __name__ == "__main__":
    main()
