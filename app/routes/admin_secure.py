"""
Secure Admin Routes for Mary V5
Protected administrative interface with comprehensive security
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from app.schemas.admin import AdminLoginRequest, AdminSessionResponse, AdminStatsResponse
from app.core.admin_security import (
    create_admin_session, validate_admin_session, destroy_admin_session,
    record_admin_failed_login, is_admin_ip_allowed, get_admin_security_stats
)
from app.core.rate_limit_config import limiter, ADMIN_LIMIT
from app.core.centralized_logging import log_audit_event, log_security_event
from app.core.dependencies import logger

router = APIRouter(prefix="/admin/v1", tags=["Admin"])
security = HTTPBearer()


def get_current_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security),
                            request: Request = None) -> Optional[str]:
    """Get current admin user from session"""
    try:
        session_id = credentials.credentials
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No session provided"
            )
        
        user = validate_admin_session(session_id, request)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )
        
        return user
    
    except Exception as e:
        logger.error("Admin authentication error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )


@router.post("/login", response_model=AdminSessionResponse)
@limiter.limit(ADMIN_LIMIT)
async def admin_login(login_data: AdminLoginRequest, request: Request):
    """Secure admin login with comprehensive protection"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Check IP allowance
    if not is_admin_ip_allowed(client_ip):
        log_security_event(
            "admin_access_denied",
            {"ip": client_ip, "reason": "ip_not_allowed"},
            correlation_id=None
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied from this IP"
        )
    
    # Record login attempt (would validate against database in production)
    user_valid = login_data.username == "admin" and login_data.password == "secure_password_hash"
    
    if not user_valid:
        locked = record_admin_failed_login(client_ip, login_data.username)
        
        if locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Account temporarily locked."
            )
        
        log_audit_event(
            "admin_login_failed",
            user=login_data.username,
            resource=f"ip:{client_ip}",
            result="failed",
            details={"ip": client_ip},
            correlation_id=None
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create secure session
    session_id = create_admin_session(login_data.username, client_ip)
    
    log_audit_event(
        "admin_login_success",
        user=login_data.username,
        resource=f"session:{session_id}",
        result="success",
        details={"ip": client_ip},
        correlation_id=None
    )
    
    return AdminSessionResponse(
        session_id=session_id,
        user=login_data.username,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
        permissions=["read", "write", "admin"]
    )


@router.post("/logout")
async def admin_logout(credentials: HTTPAuthorizationCredentials = Depends(security),
                   request: Request = None):
    """Secure admin logout"""
    try:
        session_id = credentials.credentials
        user = validate_admin_session(session_id, request)
        
        if user:
            destroyed = destroy_admin_session(session_id, user)
            
            if destroyed:
                log_audit_event(
                    "admin_logout",
                    user=user,
                    resource=f"session:{session_id}",
                    result="success",
                    correlation_id=None
                )
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error("Admin logout error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/stats", response_model=AdminStatsResponse)
async def admin_stats(current_user: str = Depends(get_current_admin_user),
                    request: Request = None):
    """Get admin statistics"""
    try:
        stats = get_admin_security_stats()
        
        log_audit_event(
            "admin_stats_accessed",
            user=current_user,
            resource="admin_stats",
            result="success",
            correlation_id=None
        )
        
        return AdminStatsResponse(
            active_sessions=stats["active_sessions"],
            locked_ips=stats["locked_ips"],
            failed_attempts=stats["failed_attempts"],
            total_events=len(stats.get("security_events", [])),
            last_updated=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error("Admin stats error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get statistics"
        )


@router.get("/session")
async def admin_session_info(credentials: HTTPAuthorizationCredentials = Depends(security),
                                request: Request = None):
    """Get current session information"""
    try:
        session_id = credentials.credentials
        user = validate_admin_session(session_id, request)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session"
            )
        
        return {
            "session_id": session_id,
            "user": user,
            "valid": True
        }
        
    except Exception as e:
        logger.error("Session info error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get session info"
        )


@router.post("/cleanup")
async def admin_cleanup(current_user: str = Depends(get_current_admin_user)):
    """Clean up expired sessions"""
    try:
        from app.core.admin_security import cleanup_admin_sessions
        cleaned_count = cleanup_admin_sessions()
        
        log_audit_event(
            "admin_cleanup",
            user=current_user,
            resource="session_cleanup",
            result="success",
            details={"cleaned_sessions": cleaned_count},
            correlation_id=None
        )
        
        return {"message": f"Cleaned up {cleaned_count} expired sessions"}
        
    except Exception as e:
        logger.error("Admin cleanup error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cleanup failed"
        )


@router.get("/security-events")
async def admin_security_events(current_user: str = Depends(get_current_admin_user),
                              limit: int = 100):
    """Get security events"""
    try:
        from app.core.centralized_logging import get_security_events
        events = get_security_events(limit)
        
        log_audit_event(
            "security_events_accessed",
            user=current_user,
            resource="security_events",
            result="success",
            details={"limit": limit, "returned": len(events)},
            correlation_id=None
        )
        
        return {"events": events}
        
    except Exception as e:
        logger.error("Security events error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get security events"
        )


@router.get("/audit-trail")
async def admin_audit_trail(current_user: str = Depends(get_current_admin_user),
                             limit: int = 100):
    """Get audit trail"""
    try:
        from app.core.centralized_logging import get_audit_trail
        events = get_audit_trail(limit)
        
        log_audit_event(
            "audit_trail_accessed",
            user=current_user,
            resource="audit_trail",
            result="success",
            details={"limit": limit, "returned": len(events)},
            correlation_id=None
        )
        
        return {"events": events}
        
    except Exception as e:
        logger.error("Audit trail error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get audit trail"
        )
