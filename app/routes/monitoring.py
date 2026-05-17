"""
Monitoring and Metrics Endpoints for Mary V5
Prometheus metrics, health checks, and operational status
"""

import os
import time
import psutil
from typing import Dict, Any
from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import PlainTextResponse

from app.core.observability import (
    telemetry, track_request_start, track_request_end,
    is_telemetry_enabled, get_prometheus_metrics
)
from app.core.alerting import is_alerting_enabled
from app.core.performance_optimizer import (
    get_performance_summary, get_optimization_recommendations,
    check_performance_thresholds
)
from app.core.tls_validator import (
    validate_tls_configuration, get_tls_recommendations,
    get_tls_validation_summary
)


router = APIRouter()


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics(request: Request):
    """Prometheus metrics endpoint"""
    if not is_telemetry_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telemetry is disabled"
        )
    
    # Track metrics request
    request_id, correlation_id = track_request_start(
        method="GET",
        path="/metrics",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        metrics_data = get_prometheus_metrics()
        
        track_request_end(request_id, status.HTTP_200_OK, len(metrics_data.encode()))
        
        return PlainTextResponse(
            content=metrics_data,
            headers={
                "Content-Type": "text/plain; version=0.0.4; charset=utf-8"
            }
        )
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate metrics: {str(e)}"
        )


@router.get("/health")
async def health_check(request: Request):
    """Health check endpoint"""
    request_id, correlation_id = track_request_start(
        method="GET",
        path="/health",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        # System health checks
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "version": os.getenv("VERSION", "5.0"),
            "environment": os.getenv("ENVIRONMENT", "dev"),
            "uptime": time.time() - psutil.boot_time(),
            "checks": {
                "telemetry": is_telemetry_enabled(),
                "alerting": is_alerting_enabled(),
                "memory": _check_memory_health(),
                "disk": _check_disk_health(),
                "cpu": _check_cpu_health()
            }
        }
        
        # Determine overall health
        all_healthy = all(
            check["status"] == "healthy" 
            for check in health_status["checks"].values()
        )
        
        if not all_healthy:
            health_status["status"] = "degraded"
        
        status_code = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        
        track_request_end(request_id, status_code)
        
        return health_status
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )


@router.get("/ready")
async def readiness_check(request: Request):
    """Readiness check endpoint"""
    request_id, correlation_id = track_request_start(
        method="GET",
        path="/ready",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        # Readiness checks
        readiness_status = {
            "status": "ready",
            "timestamp": time.time(),
            "checks": {
                "telemetry": is_telemetry_enabled(),
                "alerting": is_alerting_enabled(),
                "dependencies": _check_dependencies()
            }
        }
        
        # Determine overall readiness
        all_ready = all(
            check["status"] == "ready" 
            for check in readiness_status["checks"].values()
        )
        
        if not all_ready:
            readiness_status["status"] = "not_ready"
        
        status_code = status.HTTP_200_OK if all_ready else status.HTTP_503_SERVICE_UNAVAILABLE
        
        track_request_end(request_id, status_code)
        
        return readiness_status
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Readiness check failed: {str(e)}"
        )


@router.get("/live")
async def liveness_check(request: Request):
    """Liveness check endpoint"""
    request_id, correlation_id = track_request_start(
        method="GET",
        path="/live",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        # Simple liveness check
        liveness_status = {
            "status": "alive",
            "timestamp": time.time(),
            "pid": os.getpid()
        }
        
        track_request_end(request_id, status.HTTP_200_OK)
        
        return liveness_status
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Liveness check failed: {str(e)}"
        )


@router.get("/info")
async def system_info(request: Request):
    """System information endpoint"""
    request_id, correlation_id = track_request_start(
        method="GET",
        path="/info",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        info = {
            "service": "mary-v5",
            "version": os.getenv("VERSION", "5.0"),
            "environment": os.getenv("ENVIRONMENT", "dev"),
            "build_time": os.getenv("BUILD_TIME", "unknown"),
            "git_commit": os.getenv("GIT_COMMIT", "unknown"),
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            "features": {
                "telemetry": is_telemetry_enabled(),
                "alerting": is_alerting_enabled(),
                "defensive_monitoring": os.getenv("DEFENSIVE_MONITORING_ENABLED", "true").lower() == "true",
                "rate_limiting": os.getenv("RATE_LIMITING_ENABLED", "true").lower() == "true",
                "enterprise_security": os.getenv("ENTERPRISE_SECURITY_ENABLED", "true").lower() == "true"
            },
            "endpoints": {
                "docs": "/docs",
                "openapi": "/openapi.json",
                "metrics": "/metrics",
                "health": "/health",
                "ready": "/ready",
                "live": "/live",
                "info": "/info"
            }
        }
        
        track_request_end(request_id, status.HTTP_200_OK)
        
        return info

    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system info: {str(e)}"
        )


@router.get("/performance")
async def performance_summary(request: Request):
    """Get performance summary and recommendations"""
    if not is_telemetry_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Performance monitoring is disabled"
        )
    
    # Track performance request
    request_id, correlation_id = track_request_start(
        method="GET",
        path="/performance",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        summary = get_performance_summary()
        alerts = check_performance_thresholds()
        recommendations = get_optimization_recommendations()
        
        track_request_end(request_id, status.HTTP_200_OK)
        
        return {
            "performance": summary,
            "alerts": alerts,
            "recommendations": recommendations,
            "correlation_id": correlation_id
        }
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get performance data: {str(e)}"
        )


@router.get("/tls-validation")
async def tls_validation_summary(request: Request):
    """Get TLS validation summary"""
    if not is_telemetry_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TLS validation is disabled"
        )
    
    # Track TLS validation request
    request_id, correlation_id = track_request_start(
        method="GET",
        path="/tls-validation",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        from app.core.tls_validator import get_tls_validation_summary
        summary = get_tls_validation_summary()
        
        track_request_end(request_id, status.HTTP_200_OK)
        
        return summary
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get TLS validation data: {str(e)}"
        )


@router.post("/tls-validate")
async def validate_tls_endpoint(request: Request):
    """Validate TLS configuration for specific endpoint"""
    if not is_telemetry_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TLS validation is disabled"
        )
    
    # Track TLS validation request
    request_id, correlation_id = track_request_start(
        method="POST",
        path="/tls-validate",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        data = await request.json()
        hostname = data.get("hostname", "")
        port = int(data.get("port", "443"))
        
        if not hostname:
            track_request_end(request_id, status.HTTP_400_BAD_REQUEST)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Hostname is required"
            )
        
        from app.core.tls_validator import validate_tls_configuration, get_tls_recommendations
        validation_result = await validate_tls_configuration(hostname, port)
        recommendations = get_tls_recommendations(validation_result)
        
        track_request_end(request_id, status.HTTP_200_OK)
        
        return {
            "validation": validation_result,
            "recommendations": recommendations,
            "correlation_id": correlation_id
        }
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"TLS validation failed: {str(e)}"
        )


@router.post("/tls-validate-all")
async def validate_all_tls_endpoints(request: Request):
    """Validate TLS configuration for all endpoints"""
    if not is_telemetry_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TLS validation is disabled"
        )
    
    # Track TLS validation request
    request_id, correlation_id = track_request_start(
        method="POST",
        path="/tls-validate-all",
        source_ip=request.client.host if request.client else "unknown"
    )
    
    try:
        from app.core.tls_validator import validate_all_tls_endpoints
        results = await validate_all_tls_endpoints()
        
        track_request_end(request_id, status.HTTP_200_OK)
        
        return {
            "results": results,
            "correlation_id": correlation_id
        }
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"TLS validation failed: {str(e)}"
        )
    
    except Exception as e:
        track_request_end(request_id, status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Info check failed: {str(e)}"
        )


def _check_memory_health() -> Dict[str, Any]:
    """Check memory health"""
    try:
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        if memory_percent > 90:
            return {"status": "unhealthy", "usage_percent": memory_percent}
        elif memory_percent > 80:
            return {"status": "degraded", "usage_percent": memory_percent}
        else:
            return {"status": "healthy", "usage_percent": memory_percent}
    
    except Exception:
        return {"status": "unknown", "error": "Failed to check memory"}


def _check_disk_health() -> Dict[str, Any]:
    """Check disk health"""
    try:
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        
        if disk_percent > 90:
            return {"status": "unhealthy", "usage_percent": disk_percent}
        elif disk_percent > 80:
            return {"status": "degraded", "usage_percent": disk_percent}
        else:
            return {"status": "healthy", "usage_percent": disk_percent}
    
    except Exception:
        return {"status": "unknown", "error": "Failed to check disk"}


def _check_cpu_health() -> Dict[str, Any]:
    """Check CPU health"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        
        if cpu_percent > 90:
            return {"status": "unhealthy", "usage_percent": cpu_percent}
        elif cpu_percent > 80:
            return {"status": "degraded", "usage_percent": cpu_percent}
        else:
            return {"status": "healthy", "usage_percent": cpu_percent}
    
    except Exception:
        return {"status": "unknown", "error": "Failed to check CPU"}


def _check_dependencies() -> Dict[str, Any]:
    """Check external dependencies"""
    dependencies = {}
    
    # Check Redis (if configured)
    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            # This would be a Redis health check
            dependencies["redis"] = {"status": "ready"}
        except Exception:
            dependencies["redis"] = {"status": "not_ready", "error": "Connection failed"}
    
    # Check external services (if any)
    # Add more dependency checks as needed
    
    return {
        "status": "ready" if all(
            dep.get("status") == "ready" 
            for dep in dependencies.values()
        ) else "not_ready",
        "services": dependencies
    }
