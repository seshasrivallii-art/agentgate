import httpx

from gateway.policy_client import PolicyClient


def _client(handler):
    return PolicyClient(base_url="http://opa.test", transport=httpx.MockTransport(handler))


def test_opa_unreachable_fails_closed():
    result = PolicyClient(base_url="http://127.0.0.1:9", timeout=0.5).evaluate({"input": {}})
    assert result.decision == "deny" and not result.available


def test_opa_500_fails_closed():
    result = _client(lambda req: httpx.Response(500)).evaluate({})
    assert result.decision == "deny" and not result.available


def test_undefined_result_fails_closed():
    result = _client(lambda req: httpx.Response(200, json={})).evaluate({})
    assert result.decision == "deny"


def test_garbage_decision_fails_closed():
    result = _client(lambda req: httpx.Response(200, json={"result": {"decision": "yes please"}})).evaluate({})
    assert result.decision == "deny" and "invalid_policy_decision" in result.reasons


def test_valid_decision_passes_through():
    body = {"result": {"decision": "allow", "reasons": [], "policy_version": "v1",
                       "visible_classifications": ["internal", "public"]}}
    result = _client(lambda req: httpx.Response(200, json=body)).evaluate({})
    assert result.decision == "allow" and result.visible_classifications == ["internal", "public"]
