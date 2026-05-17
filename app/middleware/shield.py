from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.security_config import SECURITY_HEADERS, PROD_HEADERS, Environment


class SecurityShieldMiddleware(BaseHTTPMiddleware):
    """
    Middleware de seguridad centralizado.
    Aplica headers obligatorios para sector bancario y protección de identidad.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Aplicar headers base obligatorios
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value

        # En producción, agregar HSTS
        environment = request.app.state.environment
        if environment == Environment.PROD:
            for header, value in PROD_HEADERS.items():
                response.headers[header] = value

        return response