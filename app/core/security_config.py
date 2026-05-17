"""
Configuración de seguridad centralizada.
Todas las reglas están aquí para fácil auditoría.
"""

from enum import Enum


class Environment(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


# Headers de seguridad obligatorios para sector bancario (legacy - kept for compatibility)
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

# Headers solo para producción (HSTS) (legacy - kept for compatibility)
PROD_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
}

# Enhanced CSP configuration for enterprise security
CSP_DIRECTIVES = {
    "default-src": "'self'",
    "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",  # Allow Swagger/docs
    "style-src": "'self' 'unsafe-inline'",  # Allow Swagger styling
    "img-src": "'self' data: https:",
    "connect-src": "'self'",
    "font-src": "'self'",
    "object-src": "'none'",
    "media-src": "'self'",
    "frame-src": "'none'",
}

# Additional enterprise security headers
ENTERPRISE_HEADERS = {
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}

# Tiempo máximo de respuesta (segundos)
REQUEST_TIMEOUT = 10

# Tamaño máximo de body (bytes) - 1MB
MAX_BODY_SIZE = 1 * 1024 * 1024