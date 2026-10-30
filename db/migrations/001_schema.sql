-- AgentGate schema. All data is synthetic.

CREATE TABLE tenants (
  id   text PRIMARY KEY,
  name text NOT NULL
);

-- Server-side identity mapping: token client_id -> tenant and roles.
CREATE TABLE agent_registry (
  client_id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  roles     text[] NOT NULL,
  active    boolean NOT NULL DEFAULT true
);

CREATE TABLE approvers (
  username  text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  roles     text[] NOT NULL DEFAULT ARRAY['approver'],
  active    boolean NOT NULL DEFAULT true
);

CREATE TABLE documents (
  id             text PRIMARY KEY,
  tenant_id      text NOT NULL REFERENCES tenants(id),
  classification text NOT NULL CHECK (classification IN ('public', 'internal', 'finance', 'restricted')),
  title          text NOT NULL,
  body           text NOT NULL,
  search         tsvector GENERATED ALWAYS AS (to_tsvector('english', title || ' ' || body)) STORED
);
CREATE INDEX documents_search_idx ON documents USING gin (search);
CREATE INDEX documents_tenant_class_idx ON documents (tenant_id, classification);

CREATE TABLE customers (
  id                text PRIMARY KEY,
  tenant_id         text NOT NULL REFERENCES tenants(id),
  classification    text NOT NULL DEFAULT 'support',
  display_name      text NOT NULL,
  support_plan      text NOT NULL,
  open_ticket_count integer NOT NULL DEFAULT 0,
  -- Sensitive fields that the support projection must never return:
  billing_email     text,
  internal_notes    text
);

CREATE TABLE tool_requests (
  id             uuid PRIMARY KEY,
  created_at     timestamptz NOT NULL DEFAULT now(),
  agent_id       text NOT NULL,
  tenant_id      text NOT NULL,
  tool           text NOT NULL,
  arguments      jsonb NOT NULL,
  decision       text NOT NULL CHECK (decision IN ('allow', 'deny', 'require_approval', 'invalid')),
  policy_version text,
  reasons        text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE approvals (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id       uuid NOT NULL UNIQUE REFERENCES tool_requests(id),
  tenant_id        text NOT NULL,
  requested_by     text NOT NULL,
  tool             text NOT NULL,
  action_snapshot  jsonb NOT NULL,
  action_digest    text NOT NULL,
  policy_reason    text,
  status           text NOT NULL DEFAULT 'PENDING_APPROVAL'
                   CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXPIRED')),
  approver         text,
  decision_comment text,
  decided_at       timestamptz,
  expires_at       timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX approvals_tenant_status_idx ON approvals (tenant_id, status);

CREATE TABLE executions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  approval_id     uuid NOT NULL UNIQUE REFERENCES approvals(id),
  request_id      uuid NOT NULL REFERENCES tool_requests(id),
  idempotency_key text NOT NULL UNIQUE,
  status          text NOT NULL DEFAULT 'QUEUED'
                  CHECK (status IN ('QUEUED', 'EXECUTING', 'SUCCEEDED', 'FAILED')),
  attempts        integer NOT NULL DEFAULT 0,
  error           text,
  result          jsonb,
  created_at      timestamptz NOT NULL DEFAULT now(),
  started_at      timestamptz,
  finished_at     timestamptz
);
CREATE INDEX executions_queued_idx ON executions (created_at) WHERE status = 'QUEUED';

CREATE TABLE tickets (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   text NOT NULL REFERENCES tenants(id),
  customer_id text NOT NULL REFERENCES customers(id),
  title       text NOT NULL,
  description text NOT NULL,
  priority    text NOT NULL CHECK (priority IN ('low', 'normal', 'high')),
  request_id  uuid NOT NULL UNIQUE REFERENCES tool_requests(id),   -- one ticket per request, ever
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id             bigserial PRIMARY KEY,
  event_id       uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  request_id     uuid,
  tenant_id      text,
  actor          text NOT NULL,
  event_type     text NOT NULL,
  policy_version text,
  details        jsonb NOT NULL DEFAULT '{}',
  created_at     timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX audit_request_idx ON audit_events (request_id);
