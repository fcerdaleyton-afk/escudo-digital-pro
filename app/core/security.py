"""
Centralized security middleware and helpers for MARY V5

Provides:
- Security headers middleware
- Server header removal
- Request size limiting
- Simple JWT / API key auth helpers
- Simple in-memory rate limiting helper (per-IP)
"""
import os
import time
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse

try:
    import jwt
except Exception:
    jwt = None

# Security headers config
HSTS = os.getenv("HSTS_VALUE", "max-age=31536000; includeSubDomains; preload")
CSP = os.getenv("CONTENT_SECURITY_POLICY", "default-src 'self'; object-src 'none'; base-uri 'self';")

# Auth config
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
API_KEY = os.getenv("API_KEY", "")

# Rate limiting simple store
_RATE_STORE = {}
RATE_LIMIT = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

WS_MESSAGE_LIMIT = int(os.getenv("WS_MESSAGE_LIMIT", "30"))
WS_MESSAGE_WINDOW = int(os.getenv("WS_MESSAGE_WINDOW", "60"))
_WS_WS_STORE: dict[str, list[float]] = {}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Strict headers
        response.headers.setdefault("Strict-Transport-Security", HSTS)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")

        return response


class RemoveServerHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Remove any server-identifying headers
        for h in ("server", "x-powered-by", "via", "x-uvicorn-server"):
            if h in response.headers:
                del response.headers[h]
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, max_body: int = 2 * 1024 * 1024):
        super().__init__(app)
        try:
            self.max_body = int(os.getenv("MAX_BODY_SIZE", str(max_body)))
        except Exception:
            self.max_body = max_body

    async def dispatch(self, request: Request, call_next):
        # Prefer Content-Length header
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > self.max_body:
                    return JSONResponse(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, content={"detail": "Payload too large"})
            except Exception:
                pass

        # For other methods, attempt to read but limit
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > self.max_body:
                return JSONResponse(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, content={"detail": "Payload too large"})

        return await call_next(request)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip") or request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _get_websocket_client_ip(websocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for") or websocket.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = websocket.headers.get("x-real-ip") or websocket.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return websocket.client.host if websocket.client else "unknown"


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    """Very small in-memory sliding window rate limiter per IP."""
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        ip = _get_client_ip(request)
        now = time.time()
        entries = _RATE_STORE.get(ip, [])
        # purge old
        entries = [t for t in entries if t > now - RATE_WINDOW]
        if len(entries) >= RATE_LIMIT:
            return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS, content={"detail": "Rate limit exceeded"})
        entries.append(now)
        _RATE_STORE[ip] = entries
        return await call_next(request)


class WebSocketFloodProtection:
    """Protect WebSocket connections from message floods."""

    def __init__(self, limit: int = WS_MESSAGE_LIMIT, window: int = WS_MESSAGE_WINDOW):
        self.limit = limit
        self.window = window
        self.store = _WS_WS_STORE

    def allow_message(self, client_ip: str) -> bool:
        now = time.time()
        entries = self.store.get(client_ip, [])
        entries = [t for t in entries if t > now - self.window]
        if len(entries) >= self.limit:
            self.store[client_ip] = entries
            return False
        entries.append(now)
        self.store[client_ip] = entries
        return True


websocket_flood_protection = WebSocketFloodProtection()


def verify_api_request(request: Request) -> bool:
    """Verify Authorization or API key for HTTP requests."""
    # Bearer JWT takes precedence
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and jwt and JWT_SECRET:
        token = auth.split(None, 1)[1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return True
        except Exception:
            return False

    # API key header fallback
    key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if API_KEY and key and key == API_KEY:
        return True

    return False


async def websocket_verify_token(token: Optional[str]) -> bool:
    """Verify token for websocket; supports JWT or API key."""
    if not token:
        return False
    if jwt and JWT_SECRET:
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return True
        except Exception:
            return False

    if API_KEY and token == API_KEY:
        return True

    return False
