-- Approval snapshots are immutable once written, and final states stay final.
CREATE FUNCTION agentgate_guard_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.action_snapshot IS DISTINCT FROM OLD.action_snapshot
     OR NEW.action_digest IS DISTINCT FROM OLD.action_digest
     OR NEW.requested_by  IS DISTINCT FROM OLD.requested_by
     OR NEW.tenant_id     IS DISTINCT FROM OLD.tenant_id
     OR NEW.request_id    IS DISTINCT FROM OLD.request_id
     OR NEW.tool          IS DISTINCT FROM OLD.tool THEN
    RAISE EXCEPTION 'approval action snapshot is immutable';
  END IF;
  IF OLD.status <> 'PENDING_APPROVAL' AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'approval is already final (%)', OLD.status;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER approvals_guard
  BEFORE UPDATE ON approvals
  FOR EACH ROW EXECUTE FUNCTION agentgate_guard_approval();

-- Append-only through the application role. A superuser can still alter these
-- tables, so this is "append-only interface", not "tamper-proof".
CREATE FUNCTION agentgate_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;

CREATE TRIGGER audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION agentgate_append_only();

CREATE TRIGGER tool_requests_append_only
  BEFORE UPDATE OR DELETE ON tool_requests
  FOR EACH ROW EXECUTE FUNCTION agentgate_append_only();

-- Least privilege for the gateway's database role.
GRANT CONNECT ON DATABASE agentgate TO agentgate_app;
GRANT USAGE ON SCHEMA public TO agentgate_app;
GRANT SELECT ON tenants, agent_registry, approvers, documents, customers TO agentgate_app;
GRANT SELECT, INSERT ON tool_requests, tickets, audit_events TO agentgate_app;
GRANT SELECT, INSERT, UPDATE ON approvals, executions TO agentgate_app;
GRANT USAGE ON SEQUENCE audit_events_id_seq TO agentgate_app;
