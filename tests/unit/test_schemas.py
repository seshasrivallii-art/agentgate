import pytest
from pydantic import ValidationError

from gateway.schemas import CustomerLookupArgs, DocumentSearchArgs, TicketCreateArgs


def test_privilege_fields_are_rejected():
    with pytest.raises(ValidationError):
        CustomerLookupArgs.model_validate(
            {"customer_id": "customer-104", "role": "admin", "tenant_id": "tenant-b", "approved": True})


def test_customer_id_format_enforced():
    for bad in ["../etc", "customer-104; DROP TABLE customers", "", "A" * 80]:
        with pytest.raises(ValidationError):
            CustomerLookupArgs.model_validate({"customer_id": bad})


def test_search_caps():
    with pytest.raises(ValidationError):
        DocumentSearchArgs.model_validate({"query": "x" * 201})
    with pytest.raises(ValidationError):
        DocumentSearchArgs.model_validate({"query": "vpn", "limit": 1000})
    with pytest.raises(ValidationError):
        DocumentSearchArgs.model_validate({"query": "vpn", "limit": "5"})   # strict types


def test_ticket_priority_and_lengths():
    base = {"customer_id": "customer-104", "title": "VPN failure", "description": "Cannot connect."}
    assert TicketCreateArgs.model_validate(base).priority == "normal"
    with pytest.raises(ValidationError):
        TicketCreateArgs.model_validate({**base, "priority": "urgent"})
    with pytest.raises(ValidationError):
        TicketCreateArgs.model_validate({**base, "description": "x" * 2001})
    with pytest.raises(ValidationError):
        TicketCreateArgs.model_validate({**base, "title": "bad\x00title"})


def test_ticket_text_is_normalized():
    a = TicketCreateArgs.model_validate({"customer_id": "customer-104", "title": "Cafe\u0301 VPN", "description": "x"})
    b = TicketCreateArgs.model_validate({"customer_id": "customer-104", "title": "Caf\u00e9 VPN", "description": "x"})
    assert a.title == b.title
