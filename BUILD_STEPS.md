# Building AgentGate, step by step

Build in this order. Each milestone ends with a checkpoint you must pass before
moving on. The LLM is connected only in Milestone 4, after the security
boundaries already work without it.

Prerequisites: Docker with Compose v2, Python 3.11+, `jq` (for the curl
examples), and for Milestone 4 [Ollama](https://ollama.com) with a
tool-calling model (`ollama pull llama3.1:8b`).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

---

## Milestone 1: Mock tools and synthetic data

Goal: the three tools behave correctly with no identity layer and no model.

| Step | File(s) | What it does |
|---|---|---|
| 1.1 | `pyproject.toml`, `Dockerfile`, `.env.example` | Project and container definition |
| 1.2 | `db/migrations/001_schema.sql` | Tables: documents, customers, tool_requests, approvals, executions, tickets, audit_events, plus `agent_registry` and `approvers` for server-side identity mapping |
| 1.3 | `db/migrations/002_security.sql` | Immutable approval snapshots, append-only audit, least-privilege `agentgate_app` role |
| 1.4 | `db/seed/001_seed.sql`, `db/init.sh` | Two tenants, synthetic records, the injected VPN guide, `CANARY-*` leak markers |
| 1.5 | `gateway/config.py`, `gateway/db.py` | Settings and a transactional connection pool |
| 1.6 | `gateway/schemas.py` | Strict schemas (`extra="forbid"`): `role`, `tenant_id`, `approved` are rejected |
| 1.7 | `gateway/tools/documents.py`, `customers.py`, `tickets.py` | Narrow adapters: SQL-side visibility filter, fixed support projection, idempotent ticket insert |
| 1.8 | `tests/unit/test_schemas.py` | Schema tests |

Checkpoint:

```bash
docker compose up -d postgres
docker compose exec postgres psql -U agentgate_admin -d agentgate \
  -c "select id, tenant_id, classification from documents order by id"
pytest -q tests/unit/test_schemas.py
```

---

## Milestone 2: Identity and policy enforcement

Goal: cross-tenant and wrong-role requests fail safely, and every decision is audited.

| Step | File(s) | What it does |
|---|---|---|
| 2.1 | `keycloak/realm-export.json` | Service-account clients `support-agent`, `finance-agent`, `other-service` (no AgentGate audience, for negative tests), public `approval-cli`, humans `alice` (tenant-a) and `bob` (tenant-b). An audience mapper puts `agentgate` in `aud` |
| 2.2 | `policies/authz.rego` | Default-deny policy with `allow` / `deny` / `require_approval`, `visible_classifications`, and `approvals.decide` |
| 2.3 | `policies/authz_test.rego` | Policy unit tests |
| 2.4 | `gateway/auth.py` | RS256 signature, issuer, audience, expiry; then identity from the server-side registry |
| 2.5 | `gateway/policy_client.py` | OPA client that fails closed; `build_input()` is the only place OPA input is built |
| 2.6 | `gateway/audit.py` | Redacting, append-only audit writer |
| 2.7 | `gateway/authorization.py` | `handle_tool_call()`: the single authorization-and-dispatch service |
| 2.8 | `gateway/app.py` (REST parts) | `POST /v1/tools/{name}` dev endpoint calling the same service |
| 2.9 | `tests/unit/test_auth.py`, `test_policy_client.py`, `test_audit_redaction.py` | Expired, wrong-audience, wrong-issuer, tampered, `alg=none`, OPA-down tests |

Checkpoint (first end-to-end slice, then flip only the customer):

```bash
make policy-test           # all Rego tests pass
pytest -q tests/unit       # all unit tests pass
make up                    # postgres, opa, keycloak, gateway, worker
# Keycloak takes ~30 s on first start

TOKEN=$(curl -s http://localhost:8080/realms/agentgate/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=support-agent \
  -d client_secret=support-agent-dev-secret | jq -r .access_token)

# same tenant -> "ok" with only support-safe fields
curl -s localhost:8000/v1/tools/customers.lookup -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"customer_id":"customer-104"}' | jq

# other tenant -> "denied"
curl -s localhost:8000/v1/tools/customers.lookup -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"customer_id":"customer-999"}' | jq
```

---

## Milestone 3: Approval-bound writes

Goal: no ticket exists without a matching, valid, human approval.

| Step | File(s) | What it does |
|---|---|---|
| 3.1 | `gateway/approvals.py` | Canonical action + SHA-256 digest, pending approvals with expiry, approver checks, digest echo, replay protection |
| 3.2 | `gateway/authorization.py` (`_tickets_create`) | Stores the immutable action snapshot and returns `approval_required` |
| 3.3 | `gateway/execution.py` | Worker: `FOR UPDATE SKIP LOCKED` claim, full recheck, executes the stored payload, ticket + status + audit in one transaction |
| 3.4 | `gateway/app.py` (approval routes) | `GET /v1/approvals`, `GET /v1/approvals/{id}`, `POST .../approve`, `POST .../reject`, `GET /v1/audit` |
| 3.5 | `scripts/approver_cli.py` | Minimal human approval interface |
| 3.6 | `tests/unit/test_digest.py` | Digest stability tests |

Checkpoint:

```bash
curl -s localhost:8000/v1/tools/tickets.create -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"customer_id":"customer-104","title":"VPN connection failure","description":"Customer cannot connect after a client update.","priority":"normal"}' | jq
# -> "approval_required" + approval_id; no ticket exists yet

python scripts/approver_cli.py --user alice list
python scripts/approver_cli.py --user alice approve <approval_id>
python scripts/approver_cli.py --user alice show <approval_id>   # execution: SUCCEEDED
python scripts/approver_cli.py --user bob show <approval_id>     # 403: other tenant
```

---

## Milestone 4: MCP and the agent

Goal: the agent completes a legitimate lookup and proposes a ticket, through MCP only.

| Step | File(s) | What it does |
|---|---|---|
| 4.1 | `gateway/mcp_server.py` | Exactly three MCP tools at `/mcp`; each call re-validates the bearer token |
| 4.2 | `gateway/app.py` (mount + `RequireBearer`) | MCP and REST share `handle_tool_call()` |
| 4.3 | `agent/auth_client.py` | Agent token from trusted config (the model never sees it) |
| 4.4 | `agent/model_client.py` | OpenAI-compatible client (Ollama by default) |
| 4.5 | `agent/runner.py` | Bounded tool loop (`max_steps`) |

Checkpoint:

```bash
docker compose up -d --build gateway
ollama pull llama3.1:8b
python -m agent.runner "Look up customer-104 and summarize their support plan."
python -m agent.runner "Customer customer-104 cannot connect to the VPN after a client update. Propose a normal-priority ticket."
```

---

## Milestone 5: Adversarial and recovery evaluation

Goal: one repeatable command produces machine-readable results.

| Step | File(s) | What it does |
|---|---|---|
| 5.1 | `tests/helpers.py`, `tests/authorization/test_boundaries.py` | Layer A as pytest, against the live stack |
| 5.2 | `tests/recovery/test_execution.py` | Concurrency (one ticket), crash recovery, tamper, revocation, OPA outage, expiry |
| 5.3 | `evals/legitimate.jsonl`, `evals/adversarial.jsonl` | Model-driven tasks (injections live in tool results, not only prompts) |
| 5.4 | `evals/run.py`, `evals/report.py` | Layer A + Layer B runner and the metrics table |

Checkpoint:

```bash
make test                   # unit + authorization tests inside the compose network
make recovery               # stops the worker, runs recovery tests, restarts it
python -m evals.run --layer a --with-outage
python -m evals.run --layer b --naive    # gateway must hold even with a naive prompt
python -m evals.report
```

---

## Milestone 6: Portfolio packaging

| Step | File(s) |
|---|---|
| 6.1 | `Makefile`: `make up`, `make test`, `make eval` |
| 6.2 | `docs/architecture.md`: components and trust boundaries |
| 6.3 | `docs/threat-model.md`: threats, controls, and where each is tested |
| 6.4 | `docs/demo.md`: the demo script |
| 6.5 | Paste `make policy-test` output and `python -m evals.report` output into the README |

Final checkpoint: on a clean clone, `make up && make test && make eval-a && make report` works with no manual steps.
