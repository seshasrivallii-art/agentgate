from gateway.audit import redact


def test_secrets_and_content_are_redacted():
    out = redact({"authorization": "Bearer abc", "client_secret": "s3cret",
                  "description": "customer details here", "nested": {"token": "t"}})
    assert out["authorization"] == "[REDACTED]"
    assert out["client_secret"] == "[REDACTED]"
    assert out["nested"]["token"] == "[REDACTED]"
    assert out["description"]["redacted"] is True and "customer" not in str(out)


def test_long_strings_truncated():
    assert len(redact("x" * 1000)) < 220
