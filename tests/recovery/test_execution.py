"""Approval execution under replay, concurrency, crashes, revocation, and outages.

Run with the worker STOPPED so these tests control execution:
    docker compose stop worker
    docker compose --profile test run --rm tests pytest -q tests/recovery
    docker compose start worker
"""
import os
import threading
import time

import psycopg
import pytest
from psycopg.rows import dict_row

from agent.auth_client import human_token
from gateway.execution import process_one
from gateway.policy_client import PolicyClient
from tests.helpers import decide, propose_ticket, view

pytestmark = pytest.mark.stack


@pytest.fixture
def admin():
    with psycopg.connect(os.environ["ADMIN_DATABASE_URL"], autocommit=True, row_factory=dict_row) as conn:
        yield conn


def ticket_count(admin, request_id) -> int:
    return admin.execute("SELECT count(*) AS n FROM tickets WHERE request_id = %s", (request_id,)).fetchone()["n"]


@pytest.fixture
def queued():
    p = propose_ticket("recovery")
    v = view(p["approval_id"]).json()
    assert decide(p["approval_id"], v["action_digest"], human_token("alice")).status_code == 200
    time.sleep(1.5)
    v = view(p["approval_id"]).json()
    if v["execution"]["status"] != "QUEUED":
        pytest.skip("the worker is running; run `docker compose stop worker` first")
    return {**p, "execution_id": v["execution"]["id"], "digest": v["action_digest"]}


def test_two_workers_create_one_ticket(queued, admin):
    barrier, results = threading.Barrier(2), []

    def work():
        barrier.wait()
        results.append(process_one(only_execution_id=queued["execution_id"]))

    threads = [threading.Thread(target=work) for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert [r["status"] for r in results if r] == ["SUCCEEDED"]
    assert ticket_count(admin, queued["request_id"]) == 1


def test_reused_approval_rejected(queued, admin):
    assert process_one(only_execution_id=queued["execution_id"])["status"] == "SUCCEEDED"
    r = decide(queued["approval_id"], queued["digest"], human_token("alice"))
    assert r.status_code == 409
    assert process_one(only_execution_id=queued["execution_id"]) is None
    assert ticket_count(admin, queued["request_id"]) == 1


def test_crash_mid_execution_recovers_without_duplicate(queued, admin):
    def crash():
        raise RuntimeError("simulated worker crash after insert, before commit")

    with pytest.raises(RuntimeError):
        process_one(only_execution_id=queued["execution_id"], crash_hook=crash)
    assert ticket_count(admin, queued["request_id"]) == 0
    assert view(queued["approval_id"]).json()["execution"]["status"] == "QUEUED"

    assert process_one(only_execution_id=queued["execution_id"])["status"] == "SUCCEEDED"
    assert ticket_count(admin, queued["request_id"]) == 1


def test_changed_payload_after_approval_is_not_executed(queued, admin):
    # Simulate a privileged tamper that bypasses the immutability trigger.
    admin.execute("SET session_replication_role = replica")
    admin.execute("UPDATE approvals SET action_snapshot = jsonb_set(action_snapshot, '{arguments,title}', "
                  "'\"Tampered title\"') WHERE id = %s", (queued["approval_id"],))
    admin.execute("SET session_replication_role = DEFAULT")

    result = process_one(only_execution_id=queued["execution_id"])
    assert result == {"status": "FAILED", "execution_id": queued["execution_id"], "reason": "action_digest_mismatch"}
    assert ticket_count(admin, queued["request_id"]) == 0


def test_permission_revoked_after_approval(queued, admin):
    admin.execute("UPDATE agent_registry SET active = false WHERE client_id = 'support-agent'")
    try:
        result = process_one(only_execution_id=queued["execution_id"])
    finally:
        admin.execute("UPDATE agent_registry SET active = true WHERE client_id = 'support-agent'")
    assert result["status"] == "FAILED" and result["reason"] == "agent_no_longer_active"
    assert ticket_count(admin, queued["request_id"]) == 0


def test_opa_outage_defers_instead_of_executing(queued, admin):
    down = PolicyClient(base_url="http://127.0.0.1:9", timeout=0.5)
    assert process_one(policy=down, only_execution_id=queued["execution_id"])["status"] == "RETRY"
    assert ticket_count(admin, queued["request_id"]) == 0
    assert process_one(only_execution_id=queued["execution_id"])["status"] == "SUCCEEDED"


def test_expired_approval_cannot_be_approved(admin):
    p = propose_ticket("expiry")
    digest = view(p["approval_id"]).json()["action_digest"]
    admin.execute("UPDATE approvals SET expires_at = now() - interval '1 second' WHERE id = %s", (p["approval_id"],))
    assert decide(p["approval_id"], digest, human_token("alice")).status_code == 410
    assert view(p["approval_id"]).json()["status"] == "EXPIRED"


def test_snapshot_immutable_through_normal_updates(admin):
    p = propose_ticket("immutable")
    with pytest.raises(psycopg.errors.RaiseException):
        admin.execute("UPDATE approvals SET action_snapshot = '{}'::jsonb WHERE id = %s", (p["approval_id"],))
