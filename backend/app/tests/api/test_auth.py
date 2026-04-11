from types import SimpleNamespace

from app.core import auth


def test_api_token_disabled_allows_requests(monkeypatch):
    monkeypatch.delenv(auth.API_TOKEN_ENV, raising=False)
    monkeypatch.setenv(auth.ALLOW_INSECURE_NO_AUTH_ENV, "1")

    assert auth.is_api_token_enabled() is False
    assert auth.is_valid_api_token(None) is True

    request = SimpleNamespace(headers={})
    websocket = SimpleNamespace(query_params={}, headers={})
    assert auth.is_http_request_authorized(request) is True
    assert auth.is_websocket_authorized(websocket) is True


def test_http_token_validation_with_header_and_bearer(monkeypatch):
    monkeypatch.delenv(auth.ALLOW_INSECURE_NO_AUTH_ENV, raising=False)
    monkeypatch.setenv(auth.API_TOKEN_ENV, "top-secret")

    request_header = SimpleNamespace(headers={"x-kovil-token": "top-secret"})
    request_bearer = SimpleNamespace(headers={"authorization": "Bearer top-secret"})
    request_invalid = SimpleNamespace(headers={"x-kovil-token": "wrong"})

    assert auth.is_http_request_authorized(request_header) is True
    assert auth.is_http_request_authorized(request_bearer) is True
    assert auth.is_http_request_authorized(request_invalid) is False


def test_websocket_token_validation_query_header_and_bearer(monkeypatch):
    monkeypatch.delenv(auth.ALLOW_INSECURE_NO_AUTH_ENV, raising=False)
    monkeypatch.setenv(auth.API_TOKEN_ENV, "ws-secret")

    ws_query = SimpleNamespace(query_params={"token": "ws-secret"}, headers={})
    ws_header = SimpleNamespace(query_params={}, headers={"x-kovil-token": "ws-secret"})
    ws_bearer = SimpleNamespace(
        query_params={}, headers={"authorization": "Bearer ws-secret"}
    )
    ws_invalid = SimpleNamespace(query_params={}, headers={})

    assert auth.is_websocket_authorized(ws_query) is True
    assert auth.is_websocket_authorized(ws_header) is True
    assert auth.is_websocket_authorized(ws_bearer) is True
    assert auth.is_websocket_authorized(ws_invalid) is False


def test_packaged_runtime_requires_token_when_not_insecure(monkeypatch):
    monkeypatch.delenv(auth.API_TOKEN_ENV, raising=False)
    monkeypatch.delenv(auth.ALLOW_INSECURE_NO_AUTH_ENV, raising=False)
    monkeypatch.setattr(auth, "is_packaged_runtime", lambda: True)

    assert auth.is_api_token_enabled() is True
    assert auth.is_valid_api_token(None) is False


def test_require_api_token_env_flag(monkeypatch):
    monkeypatch.delenv(auth.API_TOKEN_ENV, raising=False)
    monkeypatch.delenv(auth.ALLOW_INSECURE_NO_AUTH_ENV, raising=False)
    monkeypatch.setattr(auth, "is_packaged_runtime", lambda: False)

    # Test when flag is enabled
    monkeypatch.setenv(auth.REQUIRE_API_TOKEN_ENV, "true")
    assert auth.is_api_token_enabled() is True

    # Test when flag is disabled
    monkeypatch.setenv(auth.REQUIRE_API_TOKEN_ENV, "false")
    assert auth.is_api_token_enabled() is False


def test_extract_bearer_token_edge_cases():
    # Test invalid formats
    assert auth._extract_bearer_token("") is None
    assert auth._extract_bearer_token("NotBearer token") is None
    assert auth._extract_bearer_token("Bearer") is None
    assert auth._extract_bearer_token("Bearer ") is None

    # Test case variations
    assert auth._extract_bearer_token("bearer test123") == "test123"
    assert auth._extract_bearer_token("BEARER test123") == "test123"
    assert auth._extract_bearer_token("Bearer   test123   ") == "test123"


def test_valid_token_without_expected_token(monkeypatch):
    monkeypatch.delenv(auth.API_TOKEN_ENV, raising=False)
    monkeypatch.delenv(auth.ALLOW_INSECURE_NO_AUTH_ENV, raising=False)
    monkeypatch.setattr(auth, "is_packaged_runtime", lambda: False)
    monkeypatch.setenv(auth.REQUIRE_API_TOKEN_ENV, "false")

    # When auth is disabled, any token (including None) is valid
    assert auth.is_valid_api_token(None) is True
    assert auth.is_valid_api_token("any-token") is True
