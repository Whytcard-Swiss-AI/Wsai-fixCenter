from fixcenter.privacy import contains_secret, redact, redact_value


def test_redaction_masks_sensitive_values(monkeypatch):
    monkeypatch.setenv("USERNAME", "AliceUser")
    monkeypatch.setenv("COMPUTERNAME", "AlicePC")
    raw = (
        "token=abc123 password: hunter2 Authorization=xyz Bearer aaa.bbb.ccc "
        "alice@example.com C:\\Users\\AliceUser\\secret /home/bob/private "
        "server 192.168.1.7 AlicePC https://me:pass@example.org "
        'ghp_123456789012345678901234567890 {"api_key":"json-secret"} aa:bb:cc:dd:ee:ff'
    )
    result = redact(raw)
    for secret in (
        "abc123",
        "hunter2",
        "xyz",
        "aaa.bbb.ccc",
        "alice@example.com",
        "AliceUser",
        "AlicePC",
        "192.168.1.7",
        "me:pass",
        "ghp_123",
        "json-secret",
        "aa:bb",
    ):
        assert secret.lower() not in result.lower()
    assert all(
        marker in result
        for marker in ("<REDACTED>", "<HOME>", "<EMAIL>", "<IP>", "<MAC>")
    )


def test_redaction_truncates_and_ignores_short_environment(monkeypatch):
    monkeypatch.setenv("USER", "ab")
    result = redact("x" * 20, max_chars=5)
    assert result == "xxxxx\n<TRUNCATED>"


def test_recursive_redaction_preserves_non_strings():
    value = {
        "token": "token=secret",
        "items": ["a@example.com", 3],
        "tuple": ("10.0.0.1", True),
    }
    result = redact_value(value)
    assert result["token"] == "token=<REDACTED>"
    assert result["items"] == ["<EMAIL>", 3]
    assert result["tuple"] == ("<IP>", True)


def test_common_unlabelled_secret_formats_are_detected_and_redacted():
    samples = [
        "xo" + "xb-1234567890-abcdefghijklmnop",
        "gl" + "pat-abcdefghijklmnopqrst",
        "AI" + "zaSyA123456789012345678901234567890",
        "ey" + "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        "-----BEGIN "
        + "PRIVATE KEY-----\nsynthetic-private-material\n-----END PRIVATE KEY-----",
    ]
    for secret in samples:
        assert contains_secret(secret)
        assert secret not in redact(f"prefix {secret} suffix")
