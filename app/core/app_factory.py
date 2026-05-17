"""
FastAPI application factory with proper dependency injection
"""

import asyncio
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Callable

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core.security_config import Environment, REQUEST_TIMEOUT, MAX_BODY_SIZE
from app.core.dependencies import logger
from app.core.observability import telemetry, track_request_start, track_request_end
from app.core.alerting import send_threat_alert
from app.middleware.shield import SecurityShieldMiddleware
from app.middleware.enterprise_security import EnterpriseSecurityMiddleware
from app.middleware.rate_limiter import RateLimitMiddleware
from app.middleware.defensive_monitoring import DefensiveMonitoringMiddleware
from app.middleware.production_security import ProductionSecurityMiddleware
from app.core.security import (
    SecurityHeadersMiddleware,
    RemoveServerHeaderMiddleware,
    RequestSizeLimitMiddleware,
    verify_api_request,
)
from app.core.rate_limit_config import limiter, rate_limit_handler
from app.core.enterprise_integration import initialize_enterprise_security
from app.infrastructure.redis import init_redis, close_redis


class AppFactory:
    """Factory class for creating FastAPI applications with proper configuration"""
    
    def __init__(self):
        self.logger = logger
    
    def create_middleware_stack(self, app: FastAPI) -> None:
        """Configure all middleware in the correct order"""
        
        # 1. Trusted Host (first line of defense)
        trusted_hosts = os.getenv("TRUSTED_HOSTS", "")
        if trusted_hosts:
            allowed_hosts = [host.strip() for host in trusted_hosts.split(",") if host.strip()]
        elif settings.ENVIRONMENT == Environment.DEV:
            allowed_hosts = ["*.fly.dev", "localhost", "127.0.0.1"]
        else:
            allowed_hosts = ["*.fly.dev"]

        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=allowed_hosts
        )
        
        # 2. CORS (enterprise-grade cross-origin protection)
        cors_config = self._get_cors_config()
        app.add_middleware(
            CORSMiddleware,
            **cors_config
        )

        # Global security middlewares (early in the chain)
        app.add_middleware(RemoveServerHeaderMiddleware)
        app.add_middleware(SecurityHeadersMiddleware)
        app.add_middleware(RequestSizeLimitMiddleware)
        app.add_middleware(SlowAPIMiddleware)
        
        # Apply security middleware in correct order
        app.add_middleware(DefensiveMonitoringMiddleware)
        app.add_middleware(RateLimitMiddleware)
        app.add_middleware(EnterpriseSecurityMiddleware)
        app.add_middleware(SecurityShieldMiddleware)
        
        # Production security middleware (outermost)
        if settings.ENVIRONMENT == Environment.PROD:
            app.add_middleware(ProductionSecurityMiddleware)
        
        # 7. Request tracing and timeout (custom middleware)
        app.middleware("http")(self._create_tracing_middleware())

        # 7b. Enforce API authentication for protected paths
        async def _auth_middleware(request: Request, call_next):
            path = request.url.path or ""
            # allow public auth endpoints and monitoring/docs
            if path.startswith("/api/") and not path.startswith("/api/v1/auth"):
                if not verify_api_request(request):
                    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": "Unauthorized"})
            return await call_next(request)

        app.middleware("http")(_auth_middleware)
        
        # 8. Initialize enterprise security system on startup
        async def _startup_enterprise_security():
            await initialize_enterprise_security(app)
        app.add_event_handler("startup", _startup_enterprise_security)
    
    def _get_cors_origins(self) -> list:
        """Get CORS origins based on environment with enterprise security"""
        import os
        
        # Load from environment variables for enterprise flexibility
        env_origins = os.getenv("CORS_ORIGINS", "")
        
        if env_origins:
            # Split comma-separated origins from environment
            return [origin.strip() for origin in env_origins.split(",") if origin.strip()]
        
        # Fallback to environment-based defaults
        if settings.ENVIRONMENT == Environment.PROD:
            return ["https://tudominio.com"]
        elif settings.ENVIRONMENT == Environment.STAGING:
            return ["https://staging.tudominio.com"]
        else:  # DEV
            return [
                "http://localhost:3000", 
                "http://localhost:8080",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:8080"
            ]
    
    def _get_cors_config(self) -> dict:
        """Get comprehensive CORS configuration"""
        import os
        
        return {
            "allow_origins": self._get_cors_origins(),
            "allow_credentials": os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() == "true",
            "allow_methods": os.getenv("CORS_ALLOW_METHODS", "GET,POST,PUT,DELETE,OPTIONS").split(","),
            "allow_headers": os.getenv("CORS_ALLOW_HEADERS", "Authorization,Content-Type,X-Request-ID,X-API-Key").split(","),
            "max_age": int(os.getenv("CORS_MAX_AGE", "600")),
            "expose_headers": os.getenv("CORS_EXPOSE_HEADERS", "X-Request-ID,X-Total-Count").split(","),
        }
    
    def _create_tracing_middleware(self) -> Callable:
        """Create tracing middleware with timeout and size limits"""
        
        async def tracing_middleware(request: Request, call_next):
            request_id = str(uuid.uuid4())
            request.state.request_id = request_id
            start_time = time.perf_counter()
            
            # Check content length
            if request.headers.get("content-length"):
                content_length = int(request.headers.get("content-length"))
                if content_length > MAX_BODY_SIZE:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "Payload too large", "trace_id": request_id}
                    )
            
            try:
                response = await asyncio.wait_for(
                    call_next(request), 
                    timeout=REQUEST_TIMEOUT
                )
            except asyncio.TimeoutError:
                self.logger.error(
                    "Request timeout",
                    request_id=request_id,
                    path=request.url.path,
                    method=request.method
                )
                return JSONResponse(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    content={"detail": "Request timeout", "trace_id": request_id}
                )
            except Exception as exc:
                self.logger.error(
                    "Request processing error",
                    request_id=request_id,
                    path=request.url.path,
                    method=request.method,
                    error=str(exc)
                )
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"detail": "Internal server error", "trace_id": request_id}
                )
            
            # Log successful request
            latency_ms = (time.perf_counter() - start_time) * 1000
            self.logger.info(
                "Request completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                latency_ms=round(latency_ms, 2)
            )
            
            response.headers["X-Request-ID"] = request_id
            return response
        
        return tracing_middleware
    
    def register_monitoring_endpoints(self, app: FastAPI) -> None:
        """Register health and monitoring endpoints"""
        
        @app.get("/health/live")
        async def live():
            return {"status": "alive"}
        
        @app.get("/health/ready")
        async def ready():
            return {"status": "ready"}
        
        @app.get("/")
        async def root():
            return {
                "service": settings.PROJECT_NAME,
                "version": getattr(settings, "VERSION", "1.0.0"),
                "environment": settings.ENVIRONMENT,
                "status": "online"
            }
    
    def create_lifespan_manager(self) -> Callable:
        """Create application lifespan manager"""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            app.state.environment = settings.ENVIRONMENT
            
            self.logger.info(
                "Application starting",
                project=settings.PROJECT_NAME,
                environment=settings.ENVIRONMENT,
                version=getattr(settings, "VERSION", "1.0.0")
            )
            
            # Initialize services
            try:
                await init_redis()
                self.logger.info("Redis initialized successfully")
            except Exception as exc:
                self.logger.critical("Redis initialization failed", error=str(exc))
                raise
            
            yield
            
            # Cleanup
            try:
                await close_redis()
                self.logger.info("Application shutdown completed")
            except Exception as exc:
                self.logger.error("Shutdown error", error=str(exc))
        
        return lifespan
    
    def create_app(self) -> FastAPI:
        """Create and configure FastAPI application"""
        
        # Determine docs availability
        docs_url = "/docs" if settings.ENVIRONMENT == Environment.DEV else None
        openapi_url = "/openapi.json" if settings.ENVIRONMENT == Environment.DEV else None
        
        app = FastAPI(
            title=settings.PROJECT_NAME,
            version=getattr(settings, "VERSION", "1.0.0"),
            lifespan=self.create_lifespan_manager(),
            docs_url=docs_url,
            redoc_url=None,
            openapi_url=openapi_url,
            debug=(settings.ENVIRONMENT == Environment.DEV)
        )
        
        # Configure global rate limiter
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

        # Configure middleware
        self.create_middleware_stack(app)

        # Generic exception handler: hide internal error details from clients
        async def _generic_exception_handler(request: Request, exc: Exception):
            self.logger.error("Unhandled exception", error=str(exc), path=request.url.path)
            return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": "Internal server error"})

        app.add_exception_handler(Exception, _generic_exception_handler)
        
        # Register monitoring endpoints
        self.register_monitoring_endpoints(app)
        
        # Register API routes
        self._register_routes(app)
        
        return app
    
    def _register_routes(self, app: FastAPI) -> None:
        """Register API routes with error handling"""
        try:
            from app.routes import auth, admin, monitoring, admin_secure
            from app.api import enterprise_routes
            # conversational assistant router (local safe fallback)
            from app.api import conversational

            # Include API routes
            app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
            app.include_router(admin.router, prefix="/api/v1/admin", tags=["Admin"])
            app.include_router(admin_secure.router, prefix="/api/v1/admin", tags=["Admin-Secure"])
            app.include_router(monitoring.router, prefix="/monitoring", tags=["Monitoring"])
            app.include_router(enterprise_routes.router, prefix="/api/v1/enterprise", tags=["Enterprise"])
            app.include_router(conversational.router, prefix="/api/v1/assistant", tags=["Assistant"])

            self.logger.info("All routes registered successfully")

        except ImportError as e:
            self.logger.error(f"Failed to import routes: {e}")
            raise


# Global factory instance
app_factory = AppFactory()
