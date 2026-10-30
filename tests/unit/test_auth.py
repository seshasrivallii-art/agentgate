import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from gateway.auth import AuthError, verify_jwt

ISS = "https://issuer.test/realms/agentgate"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _resolver(_token):
    return KEY.public_key()


def _token(key=KEY, **overrides):
    now = int(time.time())
    claims = {"iss": ISS, "aud": "agentgate", "iat": now, "exp": now + 300,
              "azp": "support-agent", "preferred_username": "service-account-support-agent"}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256")


def _verify(token):
    return verify_jwt(token, key_resolver=_resolver, issuer=ISS, audience="agentgate")


def test_valid_token_accepted():
    assert _verify(_token())["azp"] == "support-agent"


@pytest.mark.parametrize("overrides, reason", [
    ({"exp": int(time.time()) - 3600}, "token_expired"),
    ({"aud": "some-other-service"}, "invalid_audience"),
    ({"iss": "https://evil.test/realms/agentgate"}, "invalid_issuer"),
    ({"exp": None}, "missing_claim:exp"),
    ({"aud": None}, "missing_claim:aud"),
])
def test_bad_claims_rejected(overrides, reason):
    with pytest.raises(AuthError) as exc:
        _verify(_token(**overrides))
    assert str(exc.value) == reason


def test_wrong_signing_key_rejected():
    with pytest.raises(AuthError, match="invalid_token"):
        _verify(_token(key=OTHER_KEY))


def test_tampered_payload_rejected():
    header, payload, sig = _token().split(".")
    data = json.loads(base64.urlsafe_b64decode(payload + "=="))
    data["preferred_username"] = "service-account-admin"
    forged = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    with pytest.raises(AuthError):
        _verify(f"{header}.{forged}.{sig}")


def test_alg_none_and_hs256_rejected():
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    none_token = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'iss': ISS, 'aud': 'agentgate'})}."
    hs_token = jwt.encode({"iss": ISS, "aud": "agentgate", "exp": int(time.time()) + 60}, "secret", algorithm="HS256")
    for token in (none_token, hs_token):
        with pytest.raises(AuthError, match="unsupported_algorithm"):
            _verify(token)


def test_missing_token_rejected():
    with pytest.raises(AuthError, match="missing_token"):
        _verify(None)
