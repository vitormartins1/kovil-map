import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.utils.responses import (
    fail,
    http_exception_handler,
    ok,
    unhandled_exception_handler,
)


def test_ok_returns_payload():
    payload = {"hello": "world"}
    assert ok(payload) == {"status": "success", "data": payload}


def test_fail_raises_http_exception():
    with pytest.raises(HTTPException) as exc:
        fail("nope", code="E_TEST", status_code=422)
    assert exc.value.status_code == 422
    assert exc.value.detail["message"] == "nope"
    assert exc.value.detail["code"] == "E_TEST"


@pytest.mark.anyio
async def test_http_exception_handler_with_dict_detail():
    req = Request({"type": "http", "method": "GET", "path": "/"})
    exc = HTTPException(
        status_code=400, detail={"message": "bad request", "code": "E_BAD"}
    )

    resp = await http_exception_handler(req, exc)
    assert resp.status_code == 400
    assert b'"status":"error"' in resp.body
    assert b'"code":"E_BAD"' in resp.body


@pytest.mark.anyio
async def test_http_exception_handler_with_string_detail():
    req = Request({"type": "http", "method": "GET", "path": "/"})
    exc = HTTPException(status_code=404, detail="not found")

    resp = await http_exception_handler(req, exc)
    assert resp.status_code == 404
    assert b'"message":"not found"' in resp.body


@pytest.mark.anyio
async def test_unhandled_exception_handler_returns_500():
    req = Request({"type": "http", "method": "GET", "path": "/"})
    resp = await unhandled_exception_handler(req, RuntimeError("boom"))
    assert resp.status_code == 500
    assert b"Internal server error" in resp.body
