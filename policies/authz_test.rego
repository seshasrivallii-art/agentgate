package agentgate.authz_test

import rego.v1

import data.agentgate.authz

support_a := {"type": "agent", "id": "support-agent", "tenant_id": "tenant-a", "roles": ["support"]}

finance_a := {"type": "agent", "id": "finance-agent", "tenant_id": "tenant-a", "roles": ["finance"]}

alice := {"type": "human", "id": "alice", "tenant_id": "tenant-a", "roles": ["approver"]}

bob := {"type": "human", "id": "bob", "tenant_id": "tenant-b", "roles": ["approver"]}

customer_a := {"id": "customer-104", "tenant_id": "tenant-a", "classification": "support"}

customer_b := {"id": "customer-999", "tenant_id": "tenant-b", "classification": "support"}

approval_a := {"id": "appr-1", "type": "approval", "tenant_id": "tenant-a", "requested_by": "support-agent"}

test_same_tenant_lookup_allowed if {
	authz.decision == "allow" with input as {"subject": support_a, "action": "customers.lookup", "resource": customer_a}
}

test_cross_tenant_lookup_denied if {
	inp := {"subject": support_a, "action": "customers.lookup", "resource": customer_b}
	authz.decision == "deny" with input as inp
	"cross_tenant" in authz.reasons with input as inp
}

test_unknown_resource_denied if {
	r := {"id": "customer-x", "tenant_id": null, "classification": null}
	authz.decision == "deny" with input as {"subject": support_a, "action": "customers.lookup", "resource": r}
}

test_finance_cannot_lookup_customers if {
	authz.decision == "deny" with input as {"subject": finance_a, "action": "customers.lookup", "resource": customer_a}
}

test_ticket_requires_approval if {
	authz.decision == "require_approval" with input as {"subject": support_a, "action": "tickets.create", "resource": customer_a}
}

test_cross_tenant_ticket_denied if {
	authz.decision == "deny" with input as {"subject": support_a, "action": "tickets.create", "resource": customer_b}
}

test_finance_ticket_denied if {
	authz.decision == "deny" with input as {"subject": finance_a, "action": "tickets.create", "resource": customer_a}
}

test_internal_doc_allowed_for_support if {
	d := {"id": "doc-vpn-guide", "tenant_id": "tenant-a", "classification": "internal"}
	authz.decision == "allow" with input as {"subject": support_a, "action": "documents.read", "resource": d}
}

test_restricted_doc_denied if {
	d := {"id": "doc-restricted", "tenant_id": "tenant-a", "classification": "restricted"}
	authz.decision == "deny" with input as {"subject": support_a, "action": "documents.read", "resource": d}
}

test_finance_doc_hidden_from_support if {
	d := {"id": "doc-finance-q3", "tenant_id": "tenant-a", "classification": "finance"}
	authz.decision == "deny" with input as {"subject": support_a, "action": "documents.read", "resource": d}
}

test_finance_doc_visible_to_finance if {
	d := {"id": "doc-finance-q3", "tenant_id": "tenant-a", "classification": "finance"}
	authz.decision == "allow" with input as {"subject": finance_a, "action": "documents.read", "resource": d}
}

test_support_search_visibility if {
	inp := {"subject": support_a, "action": "documents.search", "resource": {"tenant_id": "tenant-a"}}
	authz.visible_classifications == {"public", "internal"} with input as inp
	authz.decision == "allow" with input as inp
}

test_unknown_action_denied if {
	authz.decision == "deny" with input as {"subject": support_a, "action": "customers.delete", "resource": customer_a}
}

test_empty_input_denied if {
	authz.decision == "deny" with input as {}
}

test_same_tenant_approver_can_decide if {
	authz.decision == "allow" with input as {"subject": alice, "action": "approvals.decide", "resource": approval_a}
}

test_other_tenant_approver_denied if {
	authz.decision == "deny" with input as {"subject": bob, "action": "approvals.decide", "resource": approval_a}
}

test_agent_cannot_approve if {
	inp := {"subject": support_a, "action": "approvals.decide", "resource": approval_a}
	authz.decision == "deny" with input as inp
	"agents_cannot_approve" in authz.reasons with input as inp
}

test_self_approval_denied if {
	own := object.union(approval_a, {"requested_by": "alice"})
	authz.decision == "deny" with input as {"subject": alice, "action": "approvals.decide", "resource": own}
}
