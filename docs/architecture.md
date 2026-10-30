# Architecture

```text
            untrusted                                trusted
  ┌──────────────────────────┐        ┌──────────────────────────────────────────┐
  │ User                     │        │ AgentGate (gateway container)            │
  │   │                      │        │  RequireBearer → MCP /mcp | REST /v1     │
  │   ▼                      │  MCP + │        │                                 │
  │ Agent runner + model ────┼─token─▶│  auth.authenticate()  (sig/iss/aud/exp)  │
  │ (no backend credentials) │        │        │  + agent_registry / approvers   │
  └──────────────────────────┘        │        ▼                                 │
                                      │  authorization.handle_tool_call()        │
  ┌──────────────────────────┐        │    schema → resource metadata (DB)       │
  │ Human approver (alice)   │        │    → OPA decision → adapter | approval   │
  │  approver_cli.py ────────┼─token─▶│  approvals.decide() (digest echo)        │
  └──────────────────────────┘        └───────┬──────────────────┬───────────────┘
                                              │ backend network  │ (internal: true)
  ┌──────────┐                        ┌───────▼──────┐   ┌───────▼───────┐
  │ Keycloak │ ◀── JWKS ── gateway    │  PostgreSQL  │   │      OPA      │
  └──────────┘                        └───────▲──────┘   └───────▲───────┘
                                              │                  │
                                      ┌───────┴──────────────────┴───────┐
                                      │ Worker: claim → recheck → execute │
                                      │ stored payload (one transaction)  │
                                      └──────────────────────────────────┘
```

## Trust boundaries

1. **Model → gateway.** Everything the model sends is untrusted: tool names
   and arguments are validated against strict schemas, and privileges never
   come from arguments.
2. **Token → identity.** The bearer token is verified (RS256, issuer,
   `aud=agentgate`, expiry) on every tool call, then mapped to tenant and
   roles through `agent_registry`. MCP sessions are not identity.
3. **Gateway → OPA.** OPA input is built only by `build_input()` from the
   validated identity and database metadata. Any OPA failure means deny.
4. **Approval → execution.** Approval binds to an immutable canonical action
   and its digest. The worker re-verifies the digest, approver, agent, and
   current policy, then executes only the stored payload.
5. **Gateway → database.** The gateway connects as `agentgate_app`
   (no UPDATE/DELETE on audit or requests, no DDL). The incoming agent token
   is never forwarded downstream.

## Decision flow for `customers.lookup`

```text
tool.requested → identity.validated → schema ok → load customer metadata
→ OPA(customers.lookup) → allow: support-safe projection | deny: generic denial
→ tool_requests row + audit events (same transaction)
```

## Single enforcement path

`gateway/mcp_server.py` and the REST route in `gateway/app.py` both call
`authorization.handle_tool_call()`. No other code calls the tool adapters
except the worker, which only runs approved, stored actions.
