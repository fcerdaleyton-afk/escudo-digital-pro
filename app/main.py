import asyncio
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.logger import logger
from app.core.monitoring import register_monitoring_endpoints
from app.infrastructure.redis import init_redis, close_redis
from app.middleware.shield import SecurityShieldMiddleware

# =====================================================
# 🛡️ LIFESPAN — STARTUP / SHUTDOWN
# =====================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "🚀 Iniciando Escudo Digital Mary V5",
        extra={
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT
        }
    )

    # FAIL-FAST: Dependencias críticas
    try:
        await init_redis()

        logger.info(
            "✅ Redis conectado correctamente",
            extra={"component": "redis"}
        )

    except Exception as exc:
        logger.critical(
            "❌ FALLO CRÍTICO DE INFRAESTRUCTURA",
            extra={
                "component": "redis",
                "error": str(exc)
            }
        )

        raise RuntimeError("Critical infrastructure unavailable")

    yield

    # SHUTDOWN ORDENADO
    logger.info("🛑 Iniciando apagado seguro")

    try:
        await close_redis()

        logger.info(
            "✅ Recursos liberados correctamente",
            extra={"component": "redis"}
        )

    except Exception as exc:
        logger.error(
            "⚠️ Error durante shutdown",
            extra={"error": str(exc)}
        )

    logger.info("🛡️ Escudo Digital desactivado")


# =====================================================
# 🚀 FACTORY APP
# =====================================================

def create_app() -> FastAPI:

    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        lifespan=lifespan,
        docs_url="/docs" if settings.ENVIRONMENT == "dev" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.ENVIRONMENT == "dev" else None
    )

    # =================================================
    # 🛡️ MIDDLEWARE PRINCIPAL
    # =================================================

    application.add_middleware(SecurityShieldMiddleware)

    # =================================================
    # 📊 MONITORING
    # =================================================

    register_monitoring_endpoints(application)

    # =================================================
    # 🆔 REQUEST TRACING + TIMEOUT + LOGGING
    # =================================================

    @application.middleware("http")
    async def tracing_middleware(request: Request, call_next):

        request_id = str(uuid.uuid4())

        request.state.request_id = request_id

        start_time = time.perf_counter()

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        logger.info(
            "➡️ Request iniciada",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "ip": client_ip
            }
        )

        try:

            # Protección timeout global
            response = await asyncio.wait_for(
                call_next(request),
                timeout=settings.REQUEST_TIMEOUT
            )

        except asyncio.TimeoutError:

            logger.warning(
                "⏱️ Request timeout",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "timeout": settings.REQUEST_TIMEOUT
                }
            )

            return JSONResponse(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                content={
                    "detail": "Request timeout",
                    "trace_id": request_id
                }
            )

        except Exception as exc:

            logger.exception(
                "🔥 Pipeline failure",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "error": str(exc)
                }
            )

            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "detail": (
                        "Internal Security Error"
                        if settings.ENVIRONMENT == "prod"
                        else str(exc)
                    ),
                    "trace_id": request_id
                }
            )

        finally:

            latency_ms = (
                time.perf_counter() - start_time
            ) * 1000

            logger.info(
                "✅ Request finalizada",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "latency_ms": round(latency_ms, 2)
                }
            )

        # =================================================
        # 🔐 SECURITY HEADERS
        # =================================================

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if settings.ENVIRONMENT == "prod":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response

    # =================================================
    # ⚠️ GLOBAL EXCEPTION HANDLER
    # =================================================

    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):

        request_id = getattr(
            request.state,
            "request_id",
            "unknown"
        )

        logger.exception(
            "💥 Unhandled exception",
            extra={
                "request_id": request_id,
                "path": request.url.path
            }
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": (
                    "Internal Security Error"
                    if settings.ENVIRONMENT == "prod"
                    else str(exc)
                ),
                "trace_id": request_id
            }
        )

    # =================================================
    # 🛣️ ROUTES
    # =================================================

    from app.routes import auth, health, admin

    application.include_router(
        auth.router,
        prefix="/api/v1/auth",
        tags=["Auth"]
    )

    application.include_router(
        health.router,
        prefix="/api/v1/health",
        tags=["Health"]
    )

    application.include_router(
        admin.router,
        prefix="/api/v1/admin",
        tags=["Admin"]
    )

    # =================================================
    # 🌐 ROOT
    # =================================================

    @application.get("/", tags=["Root"])
    async def root():

        return {
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "status": "online"
        }

    return application


# =====================================================
# 🚀 APP INSTANCE
# =====================================================

app = create_app()