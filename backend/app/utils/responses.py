from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


def ok(data):
    return {"status": "success", "data": data}


def fail(message, code=None, status_code=400):
    detail = {"message": message}
    if code:
        detail["code"] = code
    raise HTTPException(status_code=status_code, detail=detail)


async def http_exception_handler(request: Request, exc: HTTPException):
    detail = (
        exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    )
    return JSONResponse(
        status_code=exc.status_code, content={"status": "error", "error": detail}
    )


async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"status": "error", "error": {"message": "Internal server error"}},
    )
