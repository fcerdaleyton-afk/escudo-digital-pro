"""
Zero-Trust Authentication System for Mary V5 Enterprise
Device verification, token rotation, and continuous validation
"""

import os
import json
import time
import secrets
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import jwt
import redis.asyncio as redis
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class DeviceTrustLevel(Enum):
    """Device trust levels"""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    TRUSTED = "trusted"


class SessionStatus(Enum):
    """Session status types"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"
    EXPIRED = "expired"


@dataclass
class DeviceFingerprint:
    """Device fingerprint data"""
    device_id: str
    user_agent: str
    ip_address: str
    screen_resolution: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    platform: Optional[str] = None
    trust_level: DeviceTrustLevel = DeviceTrustLevel.UNKNOWN
    first_seen: datetime = None
    last_seen: datetime = None


@dataclass
class ZeroTrustSession:
    """Zero-trust session data"""
    session_id: str
    user_id: str
    device_id: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    status: SessionStatus
    trust_score: float
    risk_factors: List[str]
    mfa_verified: bool = False
    continuous_validation: bool = True


class DeviceFingerprinting:
    """Advanced device fingerprinting"""
    
    def __init__(self):
        self.enabled = os.getenv("DEVICE_FINGERPRINTING_ENABLED", "true").lower() == "true"
        
        # Fingerprint components
        self.fingerprint_components = [
            "user_agent", "accept_language", "accept_encoding",
            "platform", "screen_resolution", "timezone", "language"
        ]
        
        # Device database
        self.devices = {}
        self.device_trust_scores = {}
        
        # Trust thresholds
        self.trust_thresholds = {
            "new_device": 0.3,
            "known_device": 0.6,
            "trusted_device": 0.8
        }
        
        logger.info("Device fingerprinting initialized", enabled=self.enabled)
    
    def generate_device_fingerprint(self, request_data: Dict[str, Any]) -> DeviceFingerprint:
        """Generate device fingerprint from request data"""
        if not self.enabled:
            return DeviceFingerprint(
                device_id="default",
                user_agent="unknown",
                ip_address="unknown"
            )
        
        # Collect fingerprint data
        user_agent = request_data.get("user_agent", "")
        ip_address = request_data.get("ip_address", "")
        
        # Generate device ID
        fingerprint_data = "|".join([
            user_agent,
            request_data.get("accept_language", ""),
            request_data.get("accept_encoding", ""),
            request_data.get("platform", ""),
            request_data.get("screen_resolution", ""),
            request_data.get("timezone", "")
        ])
        
        device_id = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
        
        # Check if device exists
        current_time = datetime.utcnow()
        
        if device_id in self.devices:
            device = self.devices[device_id]
            device.last_seen = current_time
        else:
            device = DeviceFingerprint(
                device_id=device_id,
                user_agent=user_agent,
                ip_address=ip_address,
                screen_resolution=request_data.get("screen_resolution"),
                timezone=request_data.get("timezone"),
                language=request_data.get("language"),
                platform=request_data.get("platform"),
                first_seen=current_time,
                last_seen=current_time
            )
            self.devices[device_id] = device
        
        # Update trust level
        device.trust_level = self._calculate_trust_level(device)
        
        return device
    
    def _calculate_trust_level(self, device: DeviceFingerprint) -> DeviceTrustLevel:
        """Calculate device trust level"""
        trust_score = 0
        
        # Age factor (older devices are more trusted)
        if device.first_seen:
            days_since_first = (datetime.utcnow() - device.first_seen).days
            if days_since_first > 30:
                trust_score += 0.4
            elif days_since_first > 7:
                trust_score += 0.2
        
        # Frequency factor (frequent devices are more trusted)
        if device.last_seen and device.first_seen:
            days_active = (device.last_seen - device.first_seen).days
            if days_active > 0:
                trust_score += min(0.3, days_active * 0.01)
        
        # User agent analysis
        if self._is_legitimate_user_agent(device.user_agent):
            trust_score += 0.2
        
        # IP consistency
        if self._is_consistent_ip(device):
            trust_score += 0.1
        
        # Determine trust level
        if trust_score >= self.trust_thresholds["trusted_device"]:
            return DeviceTrustLevel.TRUSTED
        elif trust_score >= self.trust_thresholds["known_device"]:
            return DeviceTrustLevel.HIGH
        elif trust_score >= self.trust_thresholds["new_device"]:
            return DeviceTrustLevel.MEDIUM
        else:
            return DeviceTrustLevel.LOW
    
    def _is_legitimate_user_agent(self, user_agent: str) -> bool:
        """Check if user agent appears legitimate"""
        if not user_agent:
            return False
        
        # Known browsers
        legitimate_patterns = [
            "mozilla", "chrome", "firefox", "safari", "edge",
            "opera", "brave", "chromium"
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in legitimate_patterns)
    
    def _is_consistent_ip(self, device: DeviceFingerprint) -> bool:
        """Check if IP address is consistent"""
        # In a real implementation, this would check against historical IPs
        # For now, assume consistency
        return True
    
    def get_device_trust_score(self, device_id: str) -> float:
        """Get device trust score"""
        if device_id not in self.devices:
            return 0.0
        
        device = self.devices[device_id]
        trust_mapping = {
            DeviceTrustLevel.TRUSTED: 1.0,
            DeviceTrustLevel.HIGH: 0.8,
            DeviceTrustLevel.MEDIUM: 0.6,
            DeviceTrustLevel.LOW: 0.3,
            DeviceTrustLevel.UNKNOWN: 0.1
        }
        
        return trust_mapping.get(device.trust_level, 0.1)


class TokenRotationManager:
    """Advanced token rotation and management"""
    
    def __init__(self):
        self.enabled = os.getenv("TOKEN_ROTATION_ENABLED", "true").lower() == "true"
        
        # Token settings
        self.access_token_ttl = int(os.getenv("ACCESS_TOKEN_TTL", "900"))  # 15 minutes
        self.refresh_token_ttl = int(os.getenv("REFRESH_TOKEN_TTL", "604800"))  # 7 days
        self.rotation_threshold = int(os.getenv("ROTATION_THRESHOLD", "300"))  # 5 minutes
        
        # Token storage
        self.active_tokens = {}
        self.token_blacklist = set()
        
        # JWT settings
        self.jwt_secret = os.getenv("JWT_SECRET", "default_secret")
        self.jwt_algorithm = "HS256"
        
        logger.info("Token rotation manager initialized", enabled=self.enabled)
    
    def generate_token_pair(self, user_id: str, device_id: str, 
                          additional_claims: Dict[str, Any] = None) -> Tuple[str, str]:
        """Generate access and refresh token pair"""
        if not self.enabled:
            return "mock_access", "mock_refresh"
        
        current_time = datetime.utcnow()
        
        # Access token
        access_claims = {
            "user_id": user_id,
            "device_id": device_id,
            "type": "access",
            "iat": int(current_time.timestamp()),
            "exp": int((current_time + timedelta(seconds=self.access_token_ttl)).timestamp()),
            **(additional_claims or {})
        }
        
        access_token = jwt.encode(access_claims, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Refresh token
        refresh_claims = {
            "user_id": user_id,
            "device_id": device_id,
            "type": "refresh",
            "iat": int(current_time.timestamp()),
            "exp": int((current_time + timedelta(seconds=self.refresh_token_ttl)).timestamp()),
            **(additional_claims or {})
        }
        
        refresh_token = jwt.encode(refresh_claims, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Store tokens
        self.active_tokens[access_token] = {
            "user_id": user_id,
            "device_id": device_id,
            "created_at": current_time,
            "last_used": current_time,
            "type": "access"
        }
        
        self.active_tokens[refresh_token] = {
            "user_id": user_id,
            "device_id": device_id,
            "created_at": current_time,
            "last_used": current_time,
            "type": "refresh"
        }
        
        return access_token, refresh_token
    
    def validate_token(self, token: str, expected_type: str = None) -> Dict[str, Any]:
        """Validate token and return claims"""
        if not self.enabled:
            return {"valid": True, "user_id": "test", "device_id": "test"}
        
        # Check blacklist
        if token in self.token_blacklist:
            return {"valid": False, "reason": "token_blacklisted"}
        
        try:
            # Decode token
            claims = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Check token type
            if expected_type and claims.get("type") != expected_type:
                return {"valid": False, "reason": "invalid_token_type"}
            
            # Update last used
            if token in self.active_tokens:
                self.active_tokens[token]["last_used"] = datetime.utcnow()
            
            return {"valid": True, **claims}
            
        except jwt.ExpiredSignatureError:
            return {"valid": False, "reason": "token_expired"}
        except jwt.InvalidTokenError:
            return {"valid": False, "reason": "invalid_token"}
    
    def rotate_access_token(self, refresh_token: str) -> Optional[str]:
        """Rotate access token using refresh token"""
        if not self.enabled:
            return "mock_rotated_access"
        
        # Validate refresh token
        refresh_claims = self.validate_token(refresh_token, "refresh")
        
        if not refresh_claims.get("valid"):
            return None
        
        # Generate new access token
        user_id = refresh_claims["user_id"]
        device_id = refresh_claims["device_id"]
        
        current_time = datetime.utcnow()
        access_claims = {
            "user_id": user_id,
            "device_id": device_id,
            "type": "access",
            "iat": int(current_time.timestamp()),
            "exp": int((current_time + timedelta(seconds=self.access_token_ttl)).timestamp())
        }
        
        new_access_token = jwt.encode(access_claims, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Store new token
        self.active_tokens[new_access_token] = {
            "user_id": user_id,
            "device_id": device_id,
            "created_at": current_time,
            "last_used": current_time,
            "type": "access"
        }
        
        # Log token rotation
        log_audit_event(
            "token_rotated",
            user=user_id,
            resource=f"device:{device_id}",
            result="success"
        )
        
        return new_access_token
    
    def revoke_token(self, token: str):
        """Revoke token"""
        if token in self.active_tokens:
            token_info = self.active_tokens[token]
            del self.active_tokens[token]
            self.token_blacklist.add(token)
            
            log_audit_event(
                "token_revoked",
                user=token_info["user_id"],
                resource=f"device:{token_info['device_id']}",
                result="success"
            )
    
    def cleanup_expired_tokens(self):
        """Clean up expired tokens"""
        current_time = datetime.utcnow()
        expired_tokens = []
        
        for token, info in self.active_tokens.items():
            # Check if token is expired (based on JWT claims)
            try:
                claims = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
                exp_time = datetime.fromtimestamp(claims["exp"])
                
                if exp_time < current_time:
                    expired_tokens.append(token)
            except:
                expired_tokens.append(token)
        
        # Remove expired tokens
        for token in expired_tokens:
            del self.active_tokens[token]
        
        logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")


class ContinuousValidator:
    """Continuous session validation"""
    
    def __init__(self):
        self.enabled = os.getenv("CONTINUOUS_VALIDATION_ENABLED", "true").lower() == "true"
        
        # Validation thresholds
        self.max_session_idle = int(os.getenv("MAX_SESSION_IDLE", "1800"))  # 30 minutes
        self.max_session_duration = int(os.getenv("MAX_SESSION_DURATION", "28800"))  # 8 hours
        self.risk_score_threshold = float(os.getenv("RISK_SCORE_THRESHOLD", "0.7"))
        
        # Session tracking
        self.sessions = {}
        self.session_risk_scores = {}
        
        logger.info("Continuous validator initialized", enabled=self.enabled)
    
    def create_session(self, user_id: str, device_id: str, 
                      initial_trust_score: float = 0.5) -> ZeroTrustSession:
        """Create new zero-trust session"""
        current_time = datetime.utcnow()
        expires_at = current_time + timedelta(seconds=self.max_session_duration)
        
        session = ZeroTrustSession(
            session_id=secrets.token_urlsafe(32),
            user_id=user_id,
            device_id=device_id,
            created_at=current_time,
            last_activity=current_time,
            expires_at=expires_at,
            status=SessionStatus.ACTIVE,
            trust_score=initial_trust_score,
            risk_factors=[],
            continuous_validation=True
        )
        
        self.sessions[session.session_id] = session
        self.session_risk_scores[session.session_id] = initial_trust_score
        
        return session
    
    def validate_session(self, session_id: str, current_ip: str = None,
                       current_user_agent: str = None) -> Dict[str, Any]:
        """Validate session continuously"""
        if not self.enabled or session_id not in self.sessions:
            return {"valid": False, "reason": "session_not_found"}
        
        session = self.sessions[session_id]
        current_time = datetime.utcnow()
        
        # Check session expiration
        if current_time > session.expires_at:
            session.status = SessionStatus.EXPIRED
            return {"valid": False, "reason": "session_expired"}
        
        # Check idle time
        idle_time = (current_time - session.last_activity).total_seconds()
        if idle_time > self.max_session_idle:
            session.status = SessionStatus.SUSPENDED
            return {"valid": False, "reason": "session_idle"}
        
        # Check for anomalies
        risk_factors = []
        new_risk_score = session.trust_score
        
        # IP change detection
        if current_ip and self._detect_ip_anomaly(session, current_ip):
            risk_factors.append("ip_change")
            new_risk_score -= 0.2
        
        # User agent change
        if current_user_agent and self._detect_user_agent_anomaly(session, current_user_agent):
            risk_factors.append("user_agent_change")
            new_risk_score -= 0.1
        
        # Update session
        session.last_activity = current_time
        session.risk_factors.extend(risk_factors)
        session.trust_score = max(0, new_risk_score)
        self.session_risk_scores[session_id] = session.trust_score
        
        # Check if trust score is too low
        if session.trust_score < self.risk_score_threshold:
            session.status = SessionStatus.SUSPENDED
            return {
                "valid": False,
                "reason": "trust_score_low",
                "trust_score": session.trust_score,
                "risk_factors": risk_factors
            }
        
        return {
            "valid": True,
            "trust_score": session.trust_score,
            "risk_factors": risk_factors
        }
    
    def _detect_ip_anomaly(self, session: ZeroTrustSession, current_ip: str) -> bool:
        """Detect IP address anomaly"""
        # In a real implementation, this would check against known IPs for the device
        # For now, simple check for significant IP changes
        return False  # Placeholder
    
    def _detect_user_agent_anomaly(self, session: ZeroTrustSession, 
                                 current_user_agent: str) -> bool:
        """Detect user agent anomaly"""
        # Simple check for major user agent changes
        return False  # Placeholder
    
    def update_session_trust(self, session_id: str, trust_delta: float, reason: str):
        """Update session trust score"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.trust_score = max(0, min(1, session.trust_score + trust_delta))
            session.risk_factors.append(reason)
            
            log_audit_event(
                "session_trust_updated",
                user=session.user_id,
                resource=f"session:{session_id}",
                result="success",
                details={
                    "trust_score": session.trust_score,
                    "reason": reason,
                    "delta": trust_delta
                }
            )


class ZeroTrustAuthManager:
    """Main zero-trust authentication manager"""
    
    def __init__(self):
        self.enabled = os.getenv("ZERO_TRUST_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.device_fingerprinting = DeviceFingerprinting()
        self.token_manager = TokenRotationManager()
        self.continuous_validator = ContinuousValidator()
        
        # MFA settings
        self.mfa_required = os.getenv("MFA_REQUIRED", "false").lower() == "true"
        self.mfa_methods = ["totp", "sms", "email"]  # Supported MFA methods
        
        logger.info("Zero-trust auth manager initialized", enabled=self.enabled)
    
    async def authenticate(self, credentials: Dict[str, Any], 
                         request_context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform zero-trust authentication"""
        if not self.enabled:
            return {"authenticated": True, "session_id": "mock"}
        
        # Step 1: Validate credentials
        user_id = await self._validate_credentials(credentials)
        if not user_id:
            return {"authenticated": False, "reason": "invalid_credentials"}
        
        # Step 2: Generate device fingerprint
        device = self.device_fingerprinting.generate_device_fingerprint(request_context)
        
        # Step 3: Assess device trust
        device_trust = self.device_fingerprinting.get_device_trust_score(device.device_id)
        
        # Step 4: Check if MFA is required
        requires_mfa = (
            self.mfa_required or
            device_trust < 0.6 or
            device.trust_level in [DeviceTrustLevel.UNKNOWN, DeviceTrustLevel.LOW]
        )
        
        if requires_mfa:
            # Generate MFA challenge
            mfa_challenge = await self._generate_mfa_challenge(user_id, device.device_id)
            return {
                "authenticated": False,
                "requires_mfa": True,
                "mfa_challenge": mfa_challenge,
                "device_trust": device_trust
            }
        
        # Step 5: Create session
        initial_trust = min(device_trust + 0.2, 1.0)  # Boost trust for successful auth
        session = self.continuous_validator.create_session(user_id, device.device_id, initial_trust)
        
        # Step 6: Generate tokens
        access_token, refresh_token = self.token_manager.generate_token_pair(
            user_id, device.device_id, {"session_id": session.session_id}
        )
        
        # Step 7: Log successful authentication
        log_audit_event(
            "zero_trust_auth_success",
            user=user_id,
            resource=f"device:{device.device_id}",
            result="success",
            details={
                "device_trust": device_trust,
                "session_id": session.session_id
            }
        )
        
        return {
            "authenticated": True,
            "session_id": session.session_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "device_trust": device_trust,
            "session_trust": initial_trust
        }
    
    async def _validate_credentials(self, credentials: Dict[str, Any]) -> Optional[str]:
        """Validate user credentials"""
        # In a real implementation, this would check against a user database
        username = credentials.get("username")
        password = credentials.get("password")
        
        # Mock validation
        if username == "admin" and password == "secure_password":
            return "admin_user_id"
        
        return None
    
    async def _generate_mfa_challenge(self, user_id: str, device_id: str) -> Dict[str, Any]:
        """Generate MFA challenge"""
        # In a real implementation, this would generate and send MFA codes
        return {
            "challenge_id": secrets.token_urlsafe(16),
            "methods": self.mfa_methods,
            "expires_at": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        }
    
    async def validate_session(self, access_token: str, request_context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate session with continuous validation"""
        if not self.enabled:
            return {"valid": True, "user_id": "test"}
        
        # Validate access token
        token_claims = self.token_manager.validate_token(access_token, "access")
        
        if not token_claims.get("valid"):
            return {"valid": False, "reason": token_claims.get("reason", "invalid_token")}
        
        # Extract session info
        session_id = token_claims.get("session_id")
        user_id = token_claims.get("user_id")
        device_id = token_claims.get("device_id")
        
        # Continuous validation
        validation_result = self.continuous_validator.validate_session(
            session_id,
            request_context.get("ip_address"),
            request_context.get("user_agent")
        )
        
        if not validation_result.get("valid"):
            return validation_result
        
        return {
            "valid": True,
            "user_id": user_id,
            "device_id": device_id,
            "trust_score": validation_result.get("trust_score"),
            "risk_factors": validation_result.get("risk_factors", [])
        }
    
    async def rotate_token(self, refresh_token: str) -> Dict[str, Any]:
        """Rotate access token"""
        if not self.enabled:
            return {"access_token": "mock_rotated"}
        
        new_access_token = self.token_manager.rotate_access_token(refresh_token)
        
        if new_access_token:
            return {"access_token": new_access_token}
        else:
            return {"error": "invalid_refresh_token"}
    
    def get_auth_summary(self) -> Dict[str, Any]:
        """Get authentication summary"""
        if not self.enabled:
            return {"enabled": False}
        
        return {
            "enabled": True,
            "device_fingerprinting": {
                "enabled": self.device_fingerprinting.enabled,
                "total_devices": len(self.device_fingerprinting.devices)
            },
            "token_management": {
                "enabled": self.token_manager.enabled,
                "active_tokens": len(self.token_manager.active_tokens),
                "blacklisted_tokens": len(self.token_manager.token_blacklist)
            },
            "continuous_validation": {
                "enabled": self.continuous_validator.enabled,
                "active_sessions": len(self.continuous_validator.sessions)
            },
            "mfa": {
                "required": self.mfa_required,
                "methods": self.mfa_methods
            }
        }


# Global zero-trust auth manager
zero_trust_auth_manager = ZeroTrustAuthManager()


async def authenticate_zero_trust(credentials: Dict[str, Any], 
                                request_context: Dict[str, Any]) -> Dict[str, Any]:
    """Perform zero-trust authentication"""
    return await zero_trust_auth_manager.authenticate(credentials, request_context)


async def validate_session_zero_trust(access_token: str, 
                                   request_context: Dict[str, Any]) -> Dict[str, Any]:
    """Validate zero-trust session"""
    return await zero_trust_auth_manager.validate_session(access_token, request_context)


async def rotate_access_token(refresh_token: str) -> Dict[str, Any]:
    """Rotate access token"""
    return await zero_trust_auth_manager.rotate_token(refresh_token)


def get_zero_trust_summary() -> Dict[str, Any]:
    """Get zero-trust authentication summary"""
    return zero_trust_auth_manager.get_auth_summary()
