"""
Configuración de Rate Limiting para protección DDoS y fuerza bruta.
Todas las reglas centralizadas para auditoría Snyk.
"""

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request


# ============================================================
# LIMITADOR GLOBAL
# ============================================================
# Usa IP del cliente como clave (funciona con --proxy-headers)
limiter = Limiter(key_func=get_remote_address)


# ============================================================
# REGLAS POR ENDPOINT (requests por ventana de tiempo)
# ============================================================

# Endpoints de autenticación: MUY restrictivos
AUTH_LIMIT = "5/minute"        # Login, registro, token refresh
ADMIN_LIMIT = "10/minute"      # Panel admin
PASSWORD_RESET_LIMIT = "3/hour" # Recuperación de contraseña

# Endpoints sensibles: Restrictivos
SENSITIVE_LIMIT = "20/minute"  # Datos personales, transacciones

# Endpoints generales: Moderados
GENERAL_LIMIT = "100/minute"   # API pública, health checks

# Endpoints de monitoreo: Permisivos
HEALTH_LIMIT = "200/minute"    # Health checks, métricas


# ============================================================
# MANEJADOR DE EXCESO (respuesta cuando se supera el límite)
# ============================================================
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Respuesta estándar cuando un cliente supera el rate limit.
    No revela información interna.
    """
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Too many requests",
            "retry_after": exc.retry_after if hasattr(exc, 'retry_after') else 60
        }
    )