"""
Admin Panel Security for Mary V5
Provides comprehensive protection for administrative interfaces
"""

import os
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from fastapi import HTTPException, status, Request
from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class AdminSecurityManager:
    """
    Comprehensive admin panel security manager
    """
    
    def __init__(self):
        self.enabled = os.getenv("ADMIN_SECURITY_ENABLED", "true").lower() == "true"
        
        # Security configuration
        self.allowed_ips = self._load_allowed_ips()
        self.session_timeout = int(os.getenv("ADMIN_SESSION_TIMEOUT", "1800"))  # 30 minutes
        self.max_login_attempts = int(os.getenv("ADMIN_MAX_LOGIN_ATTEMPTS", "5"))
        self.lockout_duration = int(os.getenv("ADMIN_LOCKOUT_DURATION", "900"))  # 15 minutes
        self.require_2fa = os.getenv("ADMIN_REQUIRE_2FA", "true").lower() == "true"
        
        # Track active sessions and failed attempts
        self.active_sessions = {}  # {session_id: {user, ip, last_activity}}
        self.failed_attempts = {}  # {ip: [attempts, last_attempt]}
        self.locked_ips = {}  # {ip: lockout_until}
        
        logger.info("Admin security manager initialized", enabled=self.enabled)
    
    def _load_allowed_ips(self) -> Set[str]:
        """Load allowed admin IPs"""
        allowed_ips_str = os.getenv("ADMIN_ALLOWED_IPS", "")
        if not allowed_ips_str:
            return set()
        
        return set(ip.strip() for ip in allowed_ips_str.split(",") if ip.strip())
    
    def _generate_session_id(self) -> str:
        """Generate secure session ID"""
        return secrets.token_urlsafe(32)
    
    def _hash_password(self, password: str) -> str:
        """Hash password for secure storage"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed for admin access"""
        if not self.enabled:
            return True
        
        # Check if IP is locked
        if ip in self.locked_ips:
            if datetime.utcnow() < self.locked_ips[ip]:
                return False
            else:
                del self.locked_ips[ip]
                logger.info("IP lockout expired", ip=ip)
        
        # Check whitelist
        if self.allowed_ips and ip not in self.allowed_ips:
            log_security_event(
                "admin_access_denied",
                {"ip": ip, "reason": "not_in_whitelist"},
                correlation_id=None
            )
            return False
        
        return True
    
    def is_session_valid(self, session_id: str) -> bool:
        """Check if admin session is valid"""
        if not self.enabled:
            return True
        
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        
        # Check session timeout
        if datetime.utcnow() - session["last_activity"] > timedelta(seconds=self.session_timeout):
            del self.active_sessions[session_id]
            log_audit_event(
                "session_expired",
                user=session["user"],
                resource=f"session:{session_id}",
                correlation_id=None
            )
            return False
        
        return True
    
    def record_failed_login(self, ip: str, username: str = None) -> bool:
        """Record failed login attempt"""
        if not self.enabled:
            return False
        
        current_time = datetime.utcnow()
        
        # Initialize or update failed attempts
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = {"count": 0, "last_attempt": current_time}
        
        self.failed_attempts[ip]["count"] += 1
        self.failed_attempts[ip]["last_attempt"] = current_time
        
        # Check if should lock out
        if self.failed_attempts[ip]["count"] >= self.max_login_attempts:
            lockout_until = current_time + timedelta(seconds=self.lockout_duration)
            self.locked_ips[ip] = lockout_until
            
            log_security_event(
                "admin_brute_force",
                {
                    "ip": ip,
                    "username": username,
                    "attempts": self.failed_attempts[ip]["count"],
                    "lockout_until": lockout_until.isoformat()
                },
                correlation_id=None
            )
            
            # Clean failed attempts after lockout
            del self.failed_attempts[ip]
            return True
        
        return False
    
    def create_session(self, user: str, ip: str) -> str:
        """Create new admin session"""
        if not self.enabled:
            return "default-session"
        
        session_id = self._generate_session_id()
        
        self.active_sessions[session_id] = {
            "user": user,
            "ip": ip,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow()
        }
        
        log_audit_event(
            "session_created",
            user=user,
            resource=f"session:{session_id}",
            details={"ip": ip},
            correlation_id=None
        )
        
        return session_id
    
    def validate_session(self, session_id: str, request: Request) -> Optional[str]:
        """Validate and update admin session"""
        if not self.enabled:
            return "admin-user"
        
        if not self.is_session_valid(session_id):
            return None
        
        # Update last activity
        if session_id in self.active_sessions:
            self.active_sessions[session_id]["last_activity"] = datetime.utcnow()
        
        # Check IP consistency
        session = self.active_sessions[session_id]
        current_ip = request.client.host if request.client else "unknown"
        
        if session["ip"] != current_ip:
            log_security_event(
                "session_hijack_attempt",
                {
                    "session_id": session_id,
                    "original_ip": session["ip"],
                    "current_ip": current_ip,
                    "user": session["user"]
                },
                correlation_id=None
            )
            
            # Invalidate session
            del self.active_sessions[session_id]
            return None
        
        return session["user"]
    
    def destroy_session(self, session_id: str, user: str = None) -> bool:
        """Destroy admin session"""
        if not self.enabled:
            return True
        
        if session_id in self.active_sessions:
            session_user = self.active_sessions[session_id]["user"]
            del self.active_sessions[session_id]
            
            log_audit_event(
                "session_destroyed",
                user=user or session_user,
                resource=f"session:{session_id}",
                correlation_id=None
            )
            return True
        
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        if not self.enabled:
            return 0
        
        current_time = datetime.utcnow()
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if current_time - session["last_activity"] > timedelta(seconds=self.session_timeout):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            session = self.active_sessions[session_id]
            del self.active_sessions[session_id]
            
            log_audit_event(
                "session_expired",
                user=session["user"],
                resource=f"session:{session_id}",
                correlation_id=None
            )
        
        return len(expired_sessions)
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get admin security statistics"""
        return {
            "active_sessions": len(self.active_sessions),
            "locked_ips": len(self.locked_ips),
            "failed_attempts": len(self.failed_attempts),
            "allowed_ips": len(self.allowed_ips),
            "session_timeout": self.session_timeout,
            "max_login_attempts": self.max_login_attempts,
            "lockout_duration": self.lockout_duration,
            "require_2fa": self.require_2fa,
            "enabled": self.enabled
        }


# Global admin security manager
admin_security = AdminSecurityManager()


def is_admin_ip_allowed(ip: str) -> bool:
    """Check if IP is allowed for admin access"""
    return admin_security.is_ip_allowed(ip)


def record_admin_failed_login(ip: str, username: str = None) -> bool:
    """Record failed admin login attempt"""
    return admin_security.record_failed_login(ip, username)


def create_admin_session(user: str, ip: str) -> str:
    """Create new admin session"""
    return admin_security.create_session(user, ip)


def validate_admin_session(session_id: str, request: Request) -> Optional[str]:
    """Validate admin session"""
    return admin_security.validate_session(session_id, request)


def destroy_admin_session(session_id: str, user: str = None) -> bool:
    """Destroy admin session"""
    return admin_security.destroy_session(session_id, user)


def cleanup_admin_sessions() -> int:
    """Clean up expired admin sessions"""
    return admin_security.cleanup_expired_sessions()


def get_admin_security_stats() -> Dict[str, Any]:
    """Get admin security statistics"""
    return admin_security.get_security_stats()
