package agentgate.authz

import rego.v1

# Bump on every policy change; it is recorded with each audit event.
policy_version := "2026-10-30.1"

# Anything not explicitly matched is denied.
default decision := "deny"

# ---------- helpers ----------

is_agent if input.subject.type == "agent"

is_human if input.subject.type == "human"

has_role(role) if role in input.subject.roles

same_tenant if {
	is_string(input.subject.tenant_id)
	input.subject.tenant_id == input.resource.tenant_id
}

support_agent if {
	is_agent
	has_role("support")
}

finance_agent if {
	is_agent
	has_role("finance")
}

approver if {
	is_human
	has_role("approver")
}

# Document classes the caller may see. The gateway uses this as a SQL filter
# for documents.search, so restricted rows never leave the database.
visible_classifications contains c if {
	support_agent
	some c in {"public", "internal"}
}

visible_classifications contains "finance" if finance_agent

# ---------- decisions ----------

decision := "allow" if {
	input.action == "documents.search"
	is_agent
	same_tenant
	count(visible_classifications) > 0
}

decision := "allow" if {
	input.action == "documents.read"
	is_agent
	same_tenant
	input.resource.classification in visible_classifications
}

decision := "allow" if {
	input.action == "customers.lookup"
	support_agent
	same_tenant
	input.resource.classification == "support"
}

# Eligible for the approval workflow. This is NOT permission to execute.
decision := "require_approval" if {
	input.action == "tickets.create"
	support_agent
	same_tenant
	input.resource.classification == "support"
}

decision := "allow" if {
	input.action == "approvals.decide"
	approver
	same_tenant
	input.resource.requested_by != input.subject.id
}

# ---------- explanations (for audit, not for enforcement) ----------

reasons contains "cross_tenant" if not same_tenant

reasons contains "agents_cannot_approve" if {
	input.action == "approvals.decide"
	is_agent
}

reasons contains "self_approval" if {
	input.action == "approvals.decide"
	input.resource.requested_by == input.subject.id
}

reasons contains "approval_required" if decision == "require_approval"

reasons contains "no_matching_rule" if decision == "deny"
