"""
Admin Schemas for Mary V5
Pydantic models for secure admin operations
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class AdminLoginRequest(BaseModel):
    """Admin login request"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)


class AdminSessionResponse(BaseModel):
    """Admin session response"""
    session_id: str
    user: str
    expires_at: datetime
    permissions: List[str]


class AdminStatsResponse(BaseModel):
    """Admin statistics response"""
    active_sessions: int
    locked_ips: int
    failed_attempts: int
    total_events: int
    last_updated: datetime


class SecurityEvent(BaseModel):
    """Security event model"""
    timestamp: datetime
    event_type: str
    severity: str
    category: str
    correlation_id: Optional[str] = None
    details: Dict[str, Any]


class AuditEvent(BaseModel):
    """Audit event model"""
    timestamp: datetime
    event_type: str
    severity: str
    action: str
    user: Optional[str] = None
    resource: Optional[str] = None
    result: str
    details: Optional[Dict[str, Any]] = None
    correlation_id: Optional[str] = None


class LogStatsResponse(BaseModel):
    """Logging statistics response"""
    total_security_events: int
    total_audit_events: int
    configured_outputs: List[str]
    log_level: str
    retention_days: int
    enabled: bool
