import hmac
import os
import sys
from typing import Optional

from fastapi import Request, WebSocket

API_TOKEN_ENV = "KOVIL_API_TOKEN"
ALLOW_INSECURE_NO_AUTH_ENV = "KOVIL_ALLOW_INSECURE_NO_AUTH"
REQUIRE_API_TOKEN_ENV = "KOVIL_REQUIRE_API_TOKEN"


def _env_flag_enabled(name: str) -> bool:
    value = str(os.environ.get(name, "") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def is_packaged_runtime() -> bool:
    return bool(getattr(sys, "frozen", False))


def get_configured_api_token() -> str:
    return os.environ.get(API_TOKEN_ENV, "").strip()


def is_api_token_enabled() -> bool:
    if _env_flag_enabled(ALLOW_INSECURE_NO_AUTH_ENV):
        return False
    if get_configured_api_token():
        return True
    if is_packaged_runtime():
        return True
    return _env_flag_enabled(REQUIRE_API_TOKEN_ENV)


def _extract_bearer_token(authorization: str) -> Optional[str]:
    value = (authorization or "").strip()
    if not value:
        return None

    parts = value.split(" ", 1)
    if len(parts) != 2:
        return None
    if parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def is_valid_api_token(token: Optional[str]) -> bool:
    expected = get_configured_api_token()
    if not expected:
        return not is_api_token_enabled()
    if not token:
        return False
    return hmac.compare_digest(str(token), expected)


def extract_http_token(request: Request) -> Optional[str]:
    token = request.headers.get("x-kovil-token")
    if token:
        return token.strip()
    return _extract_bearer_token(request.headers.get("authorization", ""))


def extract_websocket_token(websocket: WebSocket) -> Optional[str]:
    query_token = websocket.query_params.get("token")
    if query_token:
        return query_token.strip()

    header_token = websocket.headers.get("x-kovil-token")
    if header_token:
        return header_token.strip()

    return _extract_bearer_token(websocket.headers.get("authorization", ""))


def is_http_request_authorized(request: Request) -> bool:
    return is_valid_api_token(extract_http_token(request))


def is_websocket_authorized(websocket: WebSocket) -> bool:
    return is_valid_api_token(extract_websocket_token(websocket))
