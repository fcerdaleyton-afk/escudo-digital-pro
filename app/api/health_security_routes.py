"""
MARY V5 SHIELD CORE - Health and Security API Routes
Comprehensive monitoring and security status endpoints
"""

import os
import time
import psutil
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Request, Response
from fastapi.responses import JSONResponse
import asyncio

from app.core.dependencies import logger
from app.core.centralized_logging import log_audit_event
from app.security.security_engine import get_security_engine_status
from app.monitoring.live_alerts import get_live_alert_stats, get_active_alerts
from app.detection.windows_defender import get_windows_threat_summary, get_recent_windows_threats
from app.security.threat_intelligence import get_threat_intel_stats, check_ioc_reputation
from app.middleware.api_hardening import get_api_hardening_stats
from app.middleware.security_headers import get_security_headers_stats
from app.core.logging_config import get_structured_logger, get_logging_middleware

# New FINAL HARDENING PHASE imports
from app.core.security_settings import get_security_settings, get_security_config_summary
from app.core.circuit_breaker import get_circuit_breaker_metrics, circuit_breaker_health_check
from app.security.rate_engine import get_rate_engine_statistics
from app.monitoring.threat_stream import get_threat_stream_statistics
from app.security.process_guard import get_process_guard_statistics
from app.telemetry.telemetry_engine import get_prometheus_metrics, get_telemetry_heatmaps, get_telemetry_statistics
from app.security.incident_response import get_incident_statistics
from app.core.task_manager import get_task_manager_statistics
from app.core.security_cache import get_security_cache_statistics

router = APIRouter(prefix="/health", tags=["Health & Security"])


@router.get("/")
async def health_check():
    """Basic health check endpoint"""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": os.getenv("APP_VERSION", "2.0.0"),
            "environment": os.getenv("ENVIRONMENT", "production")
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Health check failed"
        )


@router.get("/detailed")
async def detailed_health_check():
    """Detailed health check with system metrics"""
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Process metrics
        process = psutil.Process()
        process_memory = process.memory_info()
        process_cpu = process.cpu_percent()
        
        # Network metrics
        network = psutil.net_io_counters()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "system": {
                "cpu_percent": cpu_percent,
                "memory": {
                    "total_gb": memory.total / (1024**3),
                    "available_gb": memory.available / (1024**3),
                    "used_gb": memory.used / (1024**3),
                    "percent": memory.percent
                },
                "disk": {
                    "total_gb": disk.total / (1024**3),
                    "free_gb": disk.free / (1024**3),
                    "used_gb": disk.used / (1024**3),
                    "percent": (disk.used / disk.total) * 100
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                }
            },
            "process": {
                "pid": process.pid,
                "memory_mb": process_memory.rss / (1024**2),
                "cpu_percent": process_cpu,
                "threads": process.num_threads(),
                "create_time": datetime.fromtimestamp(process.create_time()).isoformat()
            },
            "uptime_seconds": time.time() - process.create_time()
        }
    except Exception as e:
        logger.error("Detailed health check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detailed health check failed"
        )


@router.get("/security/status")
async def security_status():
    """Comprehensive security status"""
    try:
        # Get security engine status
        security_engine_status = get_security_engine_status()
        
        # Get live alerts status
        live_alerts_status = get_live_alert_stats()
        
        # Get Windows threats status
        windows_threats_status = get_windows_threat_summary()
        
        # Get threat intelligence status
        threat_intel_status = get_threat_intel_stats()
        
        # Get API hardening status
        api_hardening_status = get_api_hardening_stats()
        
        # Get security headers status
        security_headers_status = get_security_headers_stats()
        
        # Calculate overall security score
        security_score = _calculate_security_score({
            "security_engine": security_engine_status,
            "live_alerts": live_alerts_status,
            "windows_threats": windows_threats_status,
            "threat_intel": threat_intel_status,
            "api_hardening": api_hardening_status,
            "security_headers": security_headers_status
        })
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": "secure" if security_score >= 80 else "warning" if security_score >= 60 else "critical",
            "security_score": security_score,
            "components": {
                "security_engine": security_engine_status,
                "live_alerts": live_alerts_status,
                "windows_threats": windows_threats_status,
                "threat_intelligence": threat_intel_status,
                "api_hardening": api_hardening_status,
                "security_headers": security_headers_status
            },
            "active_threats": {
                "total": live_alerts_status.get("active_alerts", 0),
                "critical": len([a for a in get_active_alerts(100) if a.get("priority") == "critical"]),
                "high": len([a for a in get_active_alerts(100) if a.get("priority") == "high"]),
                "medium": len([a for a in get_active_alerts(100) if a.get("priority") == "medium"]),
                "low": len([a for a in get_active_alerts(100) if a.get("priority") == "low"])
            }
        }
    except Exception as e:
        logger.error("Security status check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security status check failed"
        )


@router.get("/security/metrics")
async def security_metrics():
    """Detailed security metrics"""
    try:
        # Get component metrics
        security_engine_status = get_security_engine_status()
        live_alerts_status = get_live_alert_stats()
        windows_threats_status = get_windows_threat_summary()
        threat_intel_status = get_threat_intel_stats()
        api_hardening_status = get_api_hardening_stats()
        security_headers_status = get_security_headers_stats()
        
        # Calculate metrics
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_detection": {
                "total_events": security_engine_status.get("statistics", {}).get("events_processed", 0),
                "incidents_created": security_engine_status.get("statistics", {}).get("incidents_created", 0),
                "correlations_found": security_engine_status.get("statistics", {}).get("correlations_found", 0),
                "windows_threats": windows_threats_status.get("total_threats", 0),
                "threat_iocs": threat_intel_status.get("database_stats", {}).get("total_active", 0)
            },
            "alert_system": {
                "total_alerts": live_alerts_status.get("total_alerts", 0),
                "active_alerts": live_alerts_status.get("active_alerts", 0),
                "websocket_connections": live_alerts_status.get("websocket_connections", {}).get("active_connections", 0),
                "alerts_broadcast": live_alerts_status.get("alerts_broadcast", 0)
            },
            "api_protection": {
                "requests_processed": api_hardening_status.get("requests_processed", 0),
                "violations_detected": api_hardening_status.get("violations_detected", 0),
                "requests_blocked": api_hardening_status.get("requests_blocked", 0),
                "ddos_blocks": api_hardening_status.get("ddos_stats", {}).get("blocked_requests", 0)
            },
            "performance": {
                "cache_hit_rate": threat_intel_status.get("cache_stats", {}).get("hit_rate", 0),
                "queue_sizes": {
                    "alerts": live_alerts_status.get("queue_stats", {}).get("total_size", 0),
                    "security_engine": security_engine_status.get("queue_size", 0)
                }
            }
        }
        
        return metrics
    except Exception as e:
        logger.error("Security metrics failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security metrics failed"
        )


@router.get("/security/threats/live")
async def live_threats(limit: int = 50):
    """Get live threat information"""
    try:
        # Get active alerts
        active_alerts = get_active_alerts(limit)
        
        # Get recent Windows threats
        recent_windows_threats = get_recent_windows_threats(limit)
        
        # Combine and sort by timestamp
        all_threats = []
        
        for alert in active_alerts:
            all_threats.append({
                "type": "alert",
                "timestamp": alert.get("timestamp"),
                "severity": alert.get("priority"),
                "title": alert.get("title"),
                "description": alert.get("description"),
                "source": alert.get("source"),
                "details": alert.get("details", {})
            })
        
        for threat in recent_windows_threats:
            all_threats.append({
                "type": "windows_threat",
                "timestamp": threat.get("timestamp"),
                "severity": threat.get("severity"),
                "title": threat.get("description"),
                "description": threat.get("description"),
                "source": threat.get("source"),
                "details": threat.get("details", {})
            })
        
        # Sort by timestamp (newest first)
        all_threats.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_threats": len(all_threats),
            "threats": all_threats[:limit],
            "counts": {
                "alerts": len(active_alerts),
                "windows_threats": len(recent_windows_threats),
                "critical": len([t for t in all_threats if t["severity"] == "critical"]),
                "high": len([t for t in all_threats if t["severity"] == "high"]),
                "medium": len([t for t in all_threats if t["severity"] == "medium"]),
                "low": len([t for t in all_threats if t["severity"] == "low"])
            }
        }
    except Exception as e:
        logger.error("Live threats endpoint failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Live threats endpoint failed"
        )


@router.post("/security/ioc-check")
async def check_ioc(request: Request):
    """Check IOC reputation"""
    try:
        body = await request.json()
        ioc_type = body.get("type")
        ioc_value = body.get("value")
        
        if not ioc_type or not ioc_value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="IOC type and value are required"
            )
        
        # Check reputation
        reputation_result = await check_ioc_reputation(ioc_type, ioc_value)
        
        # Add metadata
        reputation_result["checked_at"] = datetime.utcnow().isoformat()
        reputation_result["ioc_type"] = ioc_type
        reputation_result["ioc_value"] = ioc_value
        
        # Log IOC check
        log_audit_event(
            "ioc_reputation_checked",
            resource=f"ioc:{ioc_type}:{ioc_value}",
            result="success",
            details=reputation_result
        )
        
        return reputation_result
    except Exception as e:
        logger.error("IOC check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IOC check failed"
        )


@router.get("/security/components")
async def security_components_status():
    """Get status of all security components"""
    try:
        components = {}
        
        # Security Engine
        security_engine_status = get_security_engine_status()
        components["security_engine"] = {
            "enabled": security_engine_status.get("enabled", False),
            "status": "running" if security_engine_status.get("status") == "running" else "stopped",
            "workers": security_engine_status.get("workers", 0),
            "queue_size": security_engine_status.get("queue_size", 0),
            "events_processed": security_engine_status.get("statistics", {}).get("events_processed", 0)
        }
        
        # Live Alerts
        live_alerts_status = get_live_alert_stats()
        components["live_alerts"] = {
            "enabled": live_alerts_status.get("enabled", False),
            "active_alerts": live_alerts_status.get("active_alerts", 0),
            "websocket_connections": live_alerts_status.get("websocket_connections", {}).get("active_connections", 0),
            "alerts_broadcast": live_alerts_status.get("alerts_broadcast", 0)
        }
        
        # Windows Defender
        windows_threats_status = get_windows_threat_summary()
        components["windows_defender"] = {
            "enabled": windows_threats_status.get("enabled", False),
            "is_windows": windows_threats_status.get("is_windows", False),
            "total_threats": windows_threats_status.get("total_threats", 0),
            "last_detection": windows_threats_status.get("last_detection")
        }
        
        # Threat Intelligence
        threat_intel_status = get_threat_intel_stats()
        components["threat_intelligence"] = {
            "enabled": threat_intel_status.get("enabled", False),
            "offline_mode": threat_intel_status.get("offline_mode", False),
            "cache_size": threat_intel_status.get("cache_stats", {}).get("cache_size", 0),
            "database_iocs": threat_intel_status.get("database_stats", {}).get("total_active", 0),
            "ingestion_stats": threat_intel_status.get("ingestion_stats", {})
        }
        
        # API Hardening
        api_hardening_status = get_api_hardening_stats()
        components["api_hardening"] = {
            "enabled": api_hardening_status.get("enabled", False),
            "requests_processed": api_hardening_status.get("requests_processed", 0),
            "violations_detected": api_hardening_status.get("violations_detected", 0),
            "requests_blocked": api_hardening_status.get("requests_blocked", 0)
        }
        
        # Security Headers
        security_headers_status = get_security_headers_stats()
        components["security_headers"] = {
            "enabled": security_headers_status.get("enabled", False),
            "requests_processed": security_headers_status.get("requests_processed", 0),
            "headers_applied": security_headers_status.get("headers_applied", {})
        }
        
        # Structured Logging
        structured_logger = get_structured_logger()
        components["structured_logging"] = {
            "enabled": structured_logger.enabled,
            "logs_created": structured_logger.logger_stats.get("logs_created", 0),
            "async_handler": structured_logger.async_handler.get_stats()
        }
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "components": components,
            "total_components": len(components),
            "enabled_components": len([c for c in components.values() if c.get("enabled", False)])
        }
    except Exception as e:
        logger.error("Security components status failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security components status failed"
        )


@router.get("/security/performance")
async def security_performance():
    """Security system performance metrics"""
    try:
        # Get performance data from components
        security_engine_status = get_security_engine_status()
        live_alerts_status = get_live_alert_stats()
        threat_intel_status = get_threat_intel_stats()
        api_hardening_status = get_api_hardening_stats()
        
        # Calculate performance metrics
        performance = {
            "timestamp": datetime.utcnow().isoformat(),
            "throughput": {
                "events_per_second": _calculate_events_per_second(security_engine_status),
                "alerts_per_second": _calculate_alerts_per_second(live_alerts_status),
                "requests_per_second": _calculate_requests_per_second(api_hardening_status)
            },
            "latency": {
                "event_processing_avg_ms": _calculate_avg_event_latency(security_engine_status),
                "alert_broadcast_avg_ms": _calculate_avg_alert_latency(live_alerts_status)
            },
            "efficiency": {
                "cache_hit_rate": threat_intel_status.get("cache_stats", {}).get("hit_rate", 0),
                "queue_utilization": {
                    "security_engine": security_engine_status.get("queue_size", 0) / 10000,  # Assuming max queue size
                    "alerts": live_alerts_status.get("queue_stats", {}).get("total_size", 0) / 10000
                },
                "worker_utilization": security_engine_status.get("workers", 0) / 4  # Assuming max 4 workers
            },
            "resources": {
                "memory_usage_mb": psutil.Process().memory_info().rss / (1024**2),
                "cpu_percent": psutil.Process().cpu_percent(),
                "thread_count": psutil.Process().num_threads()
            }
        }
        
        return performance
    except Exception as e:
        logger.error("Security performance metrics failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security performance metrics failed"
        )


@router.get("/security/compliance")
async def security_compliance():
    """Security compliance status"""
    try:
        compliance_checks = {
            "timestamp": datetime.utcnow().isoformat(),
            "compliance_score": 0,
            "checks": {},
            "recommendations": []
        }
        
        # Check security headers compliance
        security_headers_status = get_security_headers_stats()
        headers_score = _check_security_headers_compliance(security_headers_status)
        compliance_checks["checks"]["security_headers"] = headers_score
        
        # Check API hardening compliance
        api_hardening_status = get_api_hardening_stats()
        api_score = _check_api_hardening_compliance(api_hardening_status)
        compliance_checks["checks"]["api_hardening"] = api_score
        
        # Check logging compliance
        structured_logger = get_structured_logger()
        logging_score = _check_logging_compliance(structured_logger)
        compliance_checks["checks"]["structured_logging"] = logging_score
        
        # Check threat detection compliance
        security_engine_status = get_security_engine_status()
        detection_score = _check_threat_detection_compliance(security_engine_status)
        compliance_checks["checks"]["threat_detection"] = detection_score
        
        # Calculate overall compliance score
        total_score = sum(check["score"] for check in compliance_checks["checks"].values())
        compliance_checks["compliance_score"] = total_score / len(compliance_checks["checks"])
        
        # Generate recommendations
        compliance_checks["recommendations"] = _generate_compliance_recommendations(compliance_checks["checks"])
        
        return compliance_checks
    except Exception as e:
        logger.error("Security compliance check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security compliance check failed"
        )


@router.get("/readiness")
async def readiness_check():
    """Kubernetes readiness probe"""
    try:
        # Check critical components
        security_engine_status = get_security_engine_status()
        
        # Check if system is ready
        is_ready = (
            security_engine_status.get("enabled", False) and
            security_engine_status.get("status") == "running" and
            security_engine_status.get("queue_size", 0) < 1000  # Not overloaded
        )
        
        status_code = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE
        
        return JSONResponse(
            status_code=status_code,
            content={
                "ready": is_ready,
                "timestamp": datetime.utcnow().isoformat(),
                "checks": {
                    "security_engine": security_engine_status.get("status", "unknown"),
                    "queue_size": security_engine_status.get("queue_size", 0)
                }
            }
        )
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ready": False,
                "timestamp": datetime.utcnow().isoformat(),
                "error": "Readiness check failed"
            }
        )


@router.get("/liveness")
async def liveness_check():
    """Kubernetes liveness probe"""
    try:
        # Basic liveness check
        process = psutil.Process()
        
        # Check if process is responsive
        is_alive = process.is_running() and process.status() != psutil.STATUS_ZOMBIE
        
        status_code = status.HTTP_200_OK if is_alive else status.HTTP_503_SERVICE_UNAVAILABLE
        
        return JSONResponse(
            status_code=status_code,
            content={
                "alive": is_alive,
                "timestamp": datetime.utcnow().isoformat(),
                "process": {
                    "pid": process.pid,
                    "status": process.status(),
                    "cpu_percent": process.cpu_percent(),
                    "memory_mb": process.memory_info().rss / (1024**2)
                }
            }
        )
    except Exception as e:
        logger.error("Liveness check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "alive": False,
                "timestamp": datetime.utcnow().isoformat(),
                "error": "Liveness check failed"
            }
        )


def _calculate_security_score(components: Dict[str, Any]) -> float:
    """Calculate overall security score"""
    scores = []
    
    # Security engine score
    security_engine = components.get("security_engine", {})
    if security_engine.get("enabled"):
        score = 100
        if security_engine.get("queue_size", 0) > 1000:
            score -= 20
        if security_engine.get("status") != "running":
            score -= 50
        scores.append(score)
    
    # Live alerts score
    live_alerts = components.get("live_alerts", {})
    if live_alerts.get("enabled"):
        score = 100
        if live_alerts.get("active_alerts", 0) > 100:
            score -= 30
        scores.append(score)
    
    # Threat intelligence score
    threat_intel = components.get("threat_intelligence", {})
    if threat_intel.get("enabled"):
        score = 100
        if threat_intel.get("offline_mode"):
            score -= 20
        if threat_intel.get("cache_stats", {}).get("hit_rate", 0) < 50:
            score -= 10
        scores.append(score)
    
    # API hardening score
    api_hardening = components.get("api_hardening", {})
    if api_hardening.get("enabled"):
        score = 100
        if api_hardening.get("requests_blocked", 0) > api_hardening.get("requests_processed", 1) * 0.1:
            score -= 25
        scores.append(score)
    
    return sum(scores) / len(scores) if scores else 0


def _calculate_events_per_second(security_engine_status: Dict[str, Any]) -> float:
    """Calculate events per second"""
    stats = security_engine_status.get("statistics", {})
    events_processed = stats.get("events_processed", 0)
    uptime = security_engine_status.get("uptime_seconds", 1)
    return events_processed / uptime if uptime > 0 else 0


def _calculate_alerts_per_second(live_alerts_status: Dict[str, Any]) -> float:
    """Calculate alerts per second"""
    alerts_broadcast = live_alerts_status.get("alerts_broadcast", 0)
    uptime = live_alerts_status.get("uptime_seconds", 1)
    return alerts_broadcast / uptime if uptime > 0 else 0


def _calculate_requests_per_second(api_hardening_status: Dict[str, Any]) -> float:
    """Calculate requests per second"""
    requests_processed = api_hardening_status.get("requests_processed", 0)
    # Assuming 1 hour uptime for API hardening
    return requests_processed / 3600


def _calculate_avg_event_latency(security_engine_status: Dict[str, Any]) -> float:
    """Calculate average event processing latency"""
    # Mock calculation - in real implementation, track actual latencies
    return 10.5  # ms


def _calculate_avg_alert_latency(live_alerts_status: Dict[str, Any]) -> float:
    """Calculate average alert broadcast latency"""
    # Mock calculation - in real implementation, track actual latencies
    return 5.2  # ms


def _check_security_headers_compliance(status: Dict[str, Any]) -> Dict[str, Any]:
    """Check security headers compliance"""
    score = 100
    issues = []
    
    if not status.get("enabled"):
        score = 0
        issues.append("Security headers not enabled")
    
    headers_applied = status.get("headers_applied", {})
    required_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
    
    for header in required_headers:
        if header not in headers_applied:
            score -= 20
            issues.append(f"Missing required header: {header}")
    
    return {"score": max(0, score), "issues": issues}


def _check_api_hardening_compliance(status: Dict[str, Any]) -> Dict[str, Any]:
    """Check API hardening compliance"""
    score = 100
    issues = []
    
    if not status.get("enabled"):
        score = 0
        issues.append("API hardening not enabled")
    
    # Check violation rate
    violations = status.get("violations_detected", 0)
    requests = status.get("requests_processed", 1)
    violation_rate = violations / requests
    
    if violation_rate > 0.1:  # More than 10% violations
        score -= 30
        issues.append(f"High violation rate: {violation_rate:.2%}")
    
    return {"score": max(0, score), "issues": issues}


def _check_logging_compliance(logger) -> Dict[str, Any]:
    """Check logging compliance"""
    score = 100
    issues = []
    
    if not logger.enabled:
        score = 0
        issues.append("Structured logging not enabled")
    
    # Check log volume
    logs_created = logger.logger_stats.get("logs_created", 0)
    if logs_created < 100:
        score -= 20
        issues.append("Low log volume")
    
    return {"score": max(0, score), "issues": issues}


def _check_threat_detection_compliance(status: Dict[str, Any]) -> Dict[str, Any]:
    """Check threat detection compliance"""
    score = 100
    issues = []
    
    if not status.get("enabled"):
        score = 0
        issues.append("Threat detection not enabled")
    
    # Check event processing
    events_processed = status.get("statistics", {}).get("events_processed", 0)
    if events_processed < 10:
        score -= 30
        issues.append("Low event processing")
    
    return {"score": max(0, score), "issues": issues}


def _generate_compliance_recommendations(checks: Dict[str, Any]) -> List[str]:
    """Generate compliance recommendations"""
    recommendations = []
    
    for component, check in checks.items():
        for issue in check.get("issues", []):
            recommendations.append(f"{component}: {issue}")
    
    return recommendations


# ============================================
# FINAL HARDENING PHASE - Comprehensive Observability
# ============================================

@router.get("/configuration")
async def security_configuration():
    """Security configuration status and validation"""
    try:
        config_summary = get_security_config_summary()
        return {
            "status": "configured",
            "timestamp": datetime.utcnow().isoformat(),
            "configuration": config_summary
        }
    except Exception as e:
        logger.error("Configuration check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configuration check failed"
        )


@router.get("/circuit-breakers")
async def circuit_breakers_status():
    """Circuit breaker health and metrics"""
    try:
        metrics = get_circuit_breaker_metrics()
        health = await circuit_breaker_health_check()
        
        return {
            "status": "operational" if health["healthy"] else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": metrics,
            "health": health
        }
    except Exception as e:
        logger.error("Circuit breaker check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Circuit breaker check failed"
        )


@router.get("/rate-engine")
async def rate_engine_status():
    """Rate limiting engine statistics"""
    try:
        stats = get_rate_engine_statistics()
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": stats
        }
    except Exception as e:
        logger.error("Rate engine check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate engine check failed"
        )


@router.get("/threat-stream")
async def threat_stream_status():
    """Live threat stream statistics"""
    try:
        stats = get_threat_stream_statistics()
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": stats
        }
    except Exception as e:
        logger.error("Threat stream check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat stream check failed"
        )


@router.get("/process-guard")
async def process_guard_status():
    """Process guard statistics"""
    try:
        stats = get_process_guard_statistics()
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": stats
        }
    except Exception as e:
        logger.error("Process guard check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process guard check failed"
        )


@router.get("/telemetry")
async def telemetry_status():
    """Telemetry engine statistics"""
    try:
        stats = get_telemetry_statistics()
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": stats
        }
    except Exception as e:
        logger.error("Telemetry check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telemetry check failed"
        )


@router.get("/prometheus-metrics")
async def prometheus_metrics():
    """Prometheus metrics endpoint"""
    try:
        metrics = get_prometheus_metrics()
        return Response(
            content=metrics,
            media_type="text/plain; version=0.0.4"
        )
    except Exception as e:
        logger.error("Prometheus metrics failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Prometheus metrics failed"
        )


@router.get("/threat-heatmaps")
async def threat_heatmaps():
    """Threat heatmaps data"""
    try:
        heatmaps = get_telemetry_heatmaps()
        return {
            "status": "available",
            "timestamp": datetime.utcnow().isoformat(),
            "heatmaps": heatmaps
        }
    except Exception as e:
        logger.error("Threat heatmaps failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat heatmaps failed"
        )


@router.get("/incidents")
async def incident_response_status():
    """Incident response statistics"""
    try:
        stats = get_incident_statistics()
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": stats
        }
    except Exception as e:
        logger.error("Incident response check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Incident response check failed"
        )


@router.get("/task-manager")
async def task_manager_status():
    """Task manager statistics"""
    try:
        stats = get_task_manager_statistics()
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": stats
        }
    except Exception as e:
        logger.error("Task manager check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Task manager check failed"
        )


@router.get("/security-cache")
async def security_cache_status():
    """Security cache statistics"""
    try:
        stats = get_security_cache_statistics()
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "statistics": stats
        }
    except Exception as e:
        logger.error("Security cache check failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security cache check failed"
        )


@router.get("/comprehensive")
async def comprehensive_observability():
    """Comprehensive observability dashboard data"""
    try:
        # Gather all component statistics
        config_summary = get_security_config_summary()
        circuit_metrics = get_circuit_breaker_metrics()
        circuit_health = await circuit_breaker_health_check()
        rate_stats = get_rate_engine_statistics()
        threat_stream_stats = get_threat_stream_statistics()
        process_guard_stats = get_process_guard_statistics()
        telemetry_stats = get_telemetry_statistics()
        incident_stats = get_incident_statistics()
        task_manager_stats = get_task_manager_statistics()
        cache_stats = get_security_cache_statistics()
        
        # Calculate overall health
        overall_health = all([
            config_summary.get("enabled", False),
            circuit_health.get("healthy", False),
            rate_stats.get("enabled", False),
            threat_stream_stats.get("enabled", False),
            telemetry_stats.get("enabled", False),
            cache_stats.get("enabled", False)
        ])
        
        return {
            "status": "healthy" if overall_health else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "overall_health": overall_health,
            "components": {
                "security_configuration": config_summary,
                "circuit_breakers": {
                    "health": circuit_health,
                    "metrics": circuit_metrics
                },
                "rate_engine": rate_stats,
                "threat_stream": threat_stream_stats,
                "process_guard": process_guard_stats,
                "telemetry": telemetry_stats,
                "incident_response": incident_stats,
                "task_manager": task_manager_stats,
                "security_cache": cache_stats
            },
            "summary": {
                "total_components": 9,
                "healthy_components": sum([
                    config_summary.get("enabled", False),
                    circuit_health.get("healthy", False),
                    rate_stats.get("enabled", False),
                    threat_stream_stats.get("enabled", False),
                    telemetry_stats.get("enabled", False),
                    cache_stats.get("enabled", False)
                ]),
                "uptime": datetime.utcnow().isoformat()
            }
        }
    except Exception as e:
        logger.error("Comprehensive observability failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Comprehensive observability failed"
        )


@router.get("/live-threats")
async def live_threats_feed():
    """Live threats feed"""
    try:
        # Get recent threats from threat stream
        threat_stream_stats = get_threat_stream_statistics()
        process_guard_stats = get_process_guard_statistics()
        incident_stats = get_incident_statistics()
        
        # Get heatmaps
        heatmaps = get_telemetry_heatmaps()
        
        return {
            "status": "active",
            "timestamp": datetime.utcnow().isoformat(),
            "threat_feed": {
                "threat_stream": threat_stream_stats,
                "process_guard": process_guard_stats,
                "incidents": incident_stats,
                "heatmaps": heatmaps
            },
            "alert_level": "medium" if incident_stats.get("incidents_created", 0) < 10 else "high"
        }
    except Exception as e:
        logger.error("Live threats feed failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Live threats feed failed"
        )
