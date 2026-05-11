from fastapi import Request
from fastapi.responses import JSONResponse

async def http_exception_handler(request: Request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "HTTP Exception"}
    )

async def validation_exception_handler(request: Request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation Error"}
    )

async def general_exception_handler(request: Request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )