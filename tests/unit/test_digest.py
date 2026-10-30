from gateway.approvals import action_digest, canonical_action


def _action(**overrides):
    args = {"customer_id": "customer-104", "title": "VPN failure", "description": "x", "priority": "normal"}
    args.update(overrides)
    return canonical_action(agent_id="support-agent", tenant_id="tenant-a", tool="tickets.create",
                            arguments=args, resource_ids=["customer:customer-104"])


def test_digest_independent_of_key_order():
    a = _action()
    b = dict(reversed(list(a.items())))
    b["arguments"] = dict(reversed(list(a["arguments"].items())))
    assert action_digest(a) == action_digest(b)


def test_digest_changes_when_title_changes():
    assert action_digest(_action()) != action_digest(_action(title="Something else"))


def test_digest_binds_agent_and_tenant():
    a = _action()
    b = {**a, "tenant_id": "tenant-b"}
    c = {**a, "agent_id": "finance-agent"}
    assert len({action_digest(a), action_digest(b), action_digest(c)}) == 3
