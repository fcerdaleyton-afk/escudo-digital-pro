"""
Enterprise API Routes for Mary V5
Exposes all enterprise security features through REST API
"""

from fastapi import APIRouter, HTTPException, status, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from app.core.enterprise_integration import (
    get_enterprise_health_status, get_security_dashboard_data,
    get_enterprise_security_metrics
)
from app.detection.threat_engine import get_threat_detection_engine, get_recent_threats
from app.auth.zero_trust import (
    authenticate_zero_trust, validate_session_zero_trust,
    get_zero_trust_summary
)
from app.security.database_security import get_database_security_summary
from app.services.enterprise_features import (
    run_enterprise_health_checks, get_enterprise_summary
)
from app.services.performance_optimizer import get_performance_summary
from app.detection.windows_hardening import get_windows_threat_summary, get_recent_windows_threats

router = APIRouter(prefix="/api/v1/enterprise", tags=["Enterprise Security"])
security = HTTPBearer()


async def verify_enterprise_access(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify enterprise-level access"""
    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enterprise access token required"
        )
    
    # Validate with zero-trust system
    validation = await validate_session_zero_trust(
        credentials.credentials,
        {"endpoint": "/api/v1/enterprise"}
    )
    
    if not validation.get("valid"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enterprise access denied"
        )
    
    return validation


@router.get("/health")
async def enterprise_health():
    """Get comprehensive enterprise health status"""
    try:
        health_status = await get_enterprise_health_status()
        return health_status
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )


@router.get("/dashboard")
async def security_dashboard():
    """Get comprehensive security dashboard data"""
    try:
        dashboard_data = get_security_dashboard_data()
        return dashboard_data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dashboard data failed: {str(e)}"
        )


@router.get("/metrics")
async def enterprise_metrics():
    """Get enterprise security metrics"""
    try:
        metrics = get_enterprise_security_metrics()
        return metrics
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Metrics collection failed: {str(e)}"
        )


@router.get("/threats")
async def threat_summary():
    """Get threat detection summary"""
    try:
        threat_engine = get_threat_detection_engine()
        summary = threat_engine.get_threat_summary()
        return summary
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat summary failed: {str(e)}"
        )


@router.get("/threats/recent")
async def recent_threats(limit: int = 50):
    """Get recent threat events"""
    try:
        threats = get_recent_threats(limit)
        return {"threats": threats, "count": len(threats)}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recent threats failed: {str(e)}"
        )


@router.get("/threats/windows")
async def windows_threats():
    """Get Windows-specific threat summary"""
    try:
        summary = get_windows_threat_summary()
        return summary
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Windows threats failed: {str(e)}"
        )


@router.get("/threats/windows/recent")
async def recent_windows_threats(limit: int = 50):
    """Get recent Windows threat events"""
    try:
        threats = get_recent_windows_threats(limit)
        return {"threats": threats, "count": len(threats)}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recent Windows threats failed: {str(e)}"
        )


@router.get("/database/security")
async def database_security():
    """Get database security summary"""
    try:
        summary = get_database_security_summary()
        return summary
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database security failed: {str(e)}"
        )


@router.get("/zero-trust")
async def zero_trust_status():
    """Get zero-trust authentication status"""
    try:
        summary = get_zero_trust_summary()
        return summary
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Zero-trust status failed: {str(e)}"
        )


@router.post("/zero-trust/authenticate")
async def zero_trust_authenticate(request: Request):
    """Perform zero-trust authentication"""
    try:
        # Parse request body
        import json
        body = await request.body()
        auth_data = json.loads(body)
        
        # Extract credentials and context
        credentials = auth_data.get("credentials", {})
        request_context = {
            "user_agent": request.headers.get("user-agent", ""),
            "ip_address": request.client.host if request.client else "unknown",
            "platform": auth_data.get("platform", "unknown")
        }
        
        # Perform authentication
        auth_result = await authenticate_zero_trust(credentials, request_context)
        return auth_result
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Zero-trust authentication failed: {str(e)}"
        )


@router.post("/zero-trust/rotate-token")
async def rotate_access_token(request: Request):
    """Rotate access token"""
    try:
        import json
        body = await request.body()
        token_data = json.loads(body)
        
        refresh_token = token_data.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token required"
            )
        
        from app.auth.zero_trust import rotate_access_token
        result = await rotate_access_token(refresh_token)
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token rotation failed: {str(e)}"
        )


@router.get("/performance")
async def performance_metrics():
    """Get performance optimization metrics"""
    try:
        summary = get_performance_summary()
        return summary
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Performance metrics failed: {str(e)}"
        )


@router.get("/enterprise/features")
async def enterprise_features():
    """Get enterprise features summary"""
    try:
        summary = get_enterprise_summary()
        return summary
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Enterprise features failed: {str(e)}"
        )


@router.post("/enterprise/health-check")
async def run_health_check():
    """Run comprehensive enterprise health check"""
    try:
        health_status = await run_enterprise_health_checks()
        return health_status
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )


@router.get("/compliance/report")
async def generate_compliance_report(
    standard: str = "gdpr",
    days: int = 30
):
    """Generate compliance report"""
    try:
        from app.services.enterprise_features import ComplianceStandard, AuditEventType
        
        # Parse standard
        try:
            compliance_standard = ComplianceStandard(standard.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid compliance standard: {standard}"
            )
        
        # Generate report
        from app.services.enterprise_features import enterprise_manager
        period_start = datetime.utcnow() - timedelta(days=days)
        period_end = datetime.utcnow()
        
        report = enterprise_manager.audit_manager.generate_compliance_report(
            compliance_standard, period_start, period_end
        )
        
        return {
            "standard": standard,
            "period_days": days,
            "report": {
                "compliance_score": report.compliance_score,
                "total_events": report.total_events,
                "violations": report.violations,
                "recommendations": report.recommendations,
                "generated_at": report.generated_at.isoformat()
            }
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance report failed: {str(e)}"
        )


@router.get("/audit/summary")
async def audit_summary(days: int = 30):
    """Get audit summary for specified period"""
    try:
        from app.services.enterprise_features import enterprise_manager
        summary = enterprise_manager.audit_manager.get_audit_summary(days)
        return summary
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit summary failed: {str(e)}"
        )


@router.get("/logs/structured")
async def structured_logs(
    level: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100
):
    """Get structured logs with filtering"""
    try:
        from app.services.enterprise_features import enterprise_manager
        
        # Get log statistics
        stats = enterprise_manager.structured_logger.get_log_stats()
        
        # In a real implementation, this would query the actual log storage
        # For now, return statistics and mock data
        return {
            "statistics": stats,
            "filters": {
                "level": level,
                "event_type": event_type,
                "limit": limit
            },
            "logs": [],  # Would contain actual log entries
            "message": "Structured log query implemented - connect to log storage for full functionality"
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Structured logs failed: {str(e)}"
        )


@router.get("/status/comprehensive")
async def comprehensive_status():
    """Get comprehensive system status"""
    try:
        # Gather all status information
        health = await get_enterprise_health_status()
        dashboard = get_security_dashboard_data()
        metrics = get_enterprise_security_metrics()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "health": health,
            "dashboard": dashboard,
            "metrics": metrics,
            "status": "operational" if health.get("overall_status") != "non_operational" else "degraded"
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Comprehensive status failed: {str(e)}"
        )


# Admin-only endpoints
@router.post("/admin/shutdown")
async def emergency_shutdown(request: Request, validation: Dict = Depends(verify_enterprise_access)):
    """Emergency shutdown of enterprise security system"""
    try:
        from app.core.enterprise_integration import shutdown_enterprise_security
        await shutdown_enterprise_security()
        
        return {
            "message": "Enterprise security system shutdown initiated",
            "timestamp": datetime.utcnow().isoformat(),
            "initiated_by": validation.get("user_id", "unknown")
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Emergency shutdown failed: {str(e)}"
        )


@router.post("/admin/restart")
async def emergency_restart(request: Request, validation: Dict = Depends(verify_enterprise_access)):
    """Emergency restart of enterprise security system"""
    try:
        # Shutdown first
        from app.core.enterprise_integration import shutdown_enterprise_security
        await shutdown_enterprise_security()
        
        # Reinitialize
        from app.core.enterprise_integration import initialize_enterprise_security
        await initialize_enterprise_security()
        
        return {
            "message": "Enterprise security system restart completed",
            "timestamp": datetime.utcnow().isoformat(),
            "initiated_by": validation.get("user_id", "unknown")
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Emergency restart failed: {str(e)}"
        )
