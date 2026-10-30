"""OPA client. Every failure mode returns "deny" (fail closed)."""
import threading
from dataclasses import dataclass, field

import httpx

from .config import settings

VALID_DECISIONS = {"allow", "deny", "require_approval"}


@dataclass(frozen=True)
class PolicyResult:
    decision: str
    reasons: list[str] = field(default_factory=list)
    policy_version: str | None = None
    visible_classifications: list[str] = field(default_factory=list)
    available: bool = True   # False when OPA could not be consulted


def build_input(identity, action: str, resource: dict, request_id) -> dict:
    """The ONLY place OPA input is constructed. Subject comes from the validated
    identity, resource attributes from the database, never from tool arguments."""
    return {
        "subject": identity.opa_subject(),
        "action": action,
        "resource": {k: (None if v is None else str(v)) for k, v in resource.items()},
        "context": {"request_id": str(request_id)},
    }


class PolicyClient:
    def __init__(self, base_url: str | None = None, timeout: float | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.base_url = (base_url or settings.opa_url).rstrip("/")
        self._http = httpx.Client(timeout=timeout or settings.opa_timeout_seconds, transport=transport)

    def evaluate(self, opa_input: dict) -> PolicyResult:
        try:
            response = self._http.post(f"{self.base_url}/v1/data/agentgate/authz", json={"input": opa_input})
            response.raise_for_status()
            result = response.json().get("result")
        except (httpx.HTTPError, ValueError) as exc:
            return PolicyResult("deny", [f"policy_unavailable:{type(exc).__name__}"], available=False)

        if not isinstance(result, dict):
            return PolicyResult("deny", ["policy_undefined"], available=False)

        decision = result.get("decision")
        reasons = sorted(str(r) for r in result.get("reasons", []) or [])
        if decision not in VALID_DECISIONS:
            decision, reasons = "deny", reasons + ["invalid_policy_decision"]
        return PolicyResult(
            decision=decision,
            reasons=reasons,
            policy_version=result.get("policy_version"),
            visible_classifications=sorted(result.get("visible_classifications", []) or []),
        )


_default: PolicyClient | None = None
_lock = threading.Lock()


def get_policy_client() -> PolicyClient:
    global _default
    if _default is None:
        with _lock:
            if _default is None:
                _default = PolicyClient()
    return _default
