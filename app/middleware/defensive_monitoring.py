"""
Defensive Monitoring Middleware for Mary V5
Intelligent threat detection and automatic response system
"""

import os
import json
import asyncio
from typing import Dict, Optional, Any
from datetime import timedelta
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import status

from app.core.threat_detection import (
    ThreatEvent, AttackType, ThreatLevel,
    threat_intelligence, brute_force_detector, traffic_analyzer
)
from app.core.dependencies import logger
from app.core.observability import telemetry, track_request_start, track_request_end
from app.core.alerting import send_threat_alert
from app.infrastructure.redis import cache_set, cache_get, cache_delete


class DefensiveMonitoringMiddleware(BaseHTTPMiddleware):
    """
    Intelligent defensive monitoring middleware that:
    - Detects various attack patterns
    - Tracks authentication failures
    - Analyzes traffic anomalies
    - Implements automatic IP blocking
    - Logs structured threat events
    """
    
    def __init__(self, app, **kwargs):
        super().__init__(app, **kwargs)
        self.enabled = os.getenv("DEFENSIVE_MONITORING_ENABLED", "true").lower() == "true"
        self.block_response_enabled = os.getenv("AUTO_BLOCK_RESPONSE_ENABLED", "true").lower() == "true"
        self.threat_log_retention_hours = int(os.getenv("THREAT_LOG_RETENTION_HOURS", "168"))  # 7 days
        
        if self.enabled:
            logger.info("Defensive monitoring middleware initialized")
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP with proxy support"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return "unknown"
    
    def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant request data for analysis"""
        query_params = {}
        try:
            for key, value in request.query_params.items():
                query_params[key] = value
        except Exception:
            pass
        
        # Try to get form data or JSON body (non-destructive)
        body_data = {}
        try:
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if "application/json" in content_type:
                    # Note: This would need body to be available
                    # For now, we'll work with query params only
                    pass
                elif "application/x-www-form-urlencoded" in content_type:
                    # Form data would also need body
                    pass
        except Exception:
            pass
        
        return {
            "source_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("User-Agent", ""),
            "path": request.url.path,
            "method": request.method,
            "query_params": query_params,
            "headers": dict(request.headers),
            "content_type": request.headers.get("content-type", ""),
            "content_length": request.headers.get("content-length", "0"),
        }
    
    async def _is_ip_blocked(self, source_ip: str) -> bool:
        """Check if IP is blocked in Redis"""
        if not self.enabled:
            return False
        
        # Check in-memory block list first
        if brute_force_detector.is_ip_blocked(source_ip):
            return True
        
        # Check Redis for distributed blocking
        try:
            block_data = await cache_get(f"blocked_ip:{source_ip}")
            if block_data:
                return True
        except Exception as e:
            logger.error(f"Error checking IP block status: {e}")
        
        return False
    
    async def _block_ip(self, source_ip: str, threat_event: ThreatEvent):
        """Block IP in Redis and memory"""
        if not self.block_response_enabled:
            return
        
        block_duration = threat_event.duration_minutes * 60  # Convert to seconds
        
        # Block in Redis for distributed systems
        try:
            block_data = {
                "blocked_at": threat_event.timestamp.isoformat(),
                "threat_level": threat_event.threat_level.value,
                "attack_type": threat_event.attack_type.value,
                "fingerprint": threat_event.fingerprint,
                "details": threat_event.details,
                "duration_minutes": threat_event.duration_minutes
            }
            await cache_set(f"blocked_ip:{source_ip}", block_data, block_duration)
            logger.warning(f"IP blocked in Redis: {source_ip}", details=block_data)
        except Exception as e:
            logger.error(f"Error blocking IP in Redis: {e}")
    
    async def _log_threat_event(self, threat_event: ThreatEvent, correlation_id: str = None):
        """Log structured threat event"""
        try:
            # Track threat event with telemetry
            await telemetry.track_threat_event(threat_event, correlation_id)
            
            # Send alert if severity is high enough
            await send_threat_alert(threat_event, correlation_id)
            
            # Store in Redis for analysis and retention
            await cache_set(
                f"threat:{threat_event.fingerprint}",
                {
                    "timestamp": threat_event.timestamp.isoformat(),
                    "attack_type": threat_event.attack_type.value,
                    "threat_level": threat_event.threat_level.value,
                    "source_ip": threat_event.source_ip,
                    "fingerprint": threat_event.fingerprint,
                    "blocked": threat_event.blocked,
                    "details": threat_event.details
                },
                self.threat_log_retention_hours * 3600
            )
            
        except Exception as e:
            logger.error(f"Error logging threat event: {e}")
    
    async def _handle_auth_failure(self, request: Request, username: str = None):
        """Handle authentication failure"""
        if not self.enabled:
            return
        
        source_ip = self._get_client_ip(request)
        
        # Record failed attempt
        threat_event = brute_force_detector.record_failed_attempt(source_ip, username)
        
        if threat_event:
            await self._log_threat_event(threat_event)
            await self._block_ip(source_ip, threat_event)
    
    async def _analyze_request_threats(self, request_data: Dict[str, Any]) -> list:
        """Analyze request for various threats"""
        threats = []
        
        if not self.enabled:
            return threats
        
        # Pattern-based threat detection
        pattern_threats = threat_intelligence.analyze_request(request_data)
        threats.extend(pattern_threats)
        
        # Traffic analysis
        traffic_threat = traffic_analyzer.record_request(
            request_data["source_ip"],
            request_data["path"],
            request_data["method"]
        )
        if traffic_threat:
            threats.append(traffic_threat)
        
        return threats
    
    async def _create_block_response(self, threat_events: list) -> JSONResponse:
        """Create standardized block response"""
        if not threat_events:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Access denied"}
            )
        
        # Use the highest severity threat
        highest_threat = max(threat_events, key=lambda t: (
            t.threat_level == ThreatLevel.CRITICAL,
            t.threat_level == ThreatLevel.HIGH,
            t.threat_level == ThreatLevel.MEDIUM,
            t.threat_level == ThreatLevel.LOW
        ))
        
        response_data = {
            "detail": "Access denied - suspicious activity detected",
            "threat_level": highest_threat.threat_level.value,
            "attack_type": highest_threat.attack_type.value,
            "fingerprint": highest_threat.fingerprint,
            "blocked_until": (highest_threat.timestamp + 
                            timedelta(minutes=highest_threat.duration_minutes)).isoformat()
        }
        
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=response_data,
            headers={
                "X-Threat-Detected": "true",
                "X-Threat-Level": highest_threat.threat_level.value,
                "X-Attack-Type": highest_threat.attack_type.value,
                "X-Block-Duration": str(highest_threat.duration_minutes),
            }
        )
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch method"""
        if not self.enabled:
            return await call_next(request)
        
        # Extract request data for analysis
        request_data = self._extract_request_data(request)
        source_ip = request_data["source_ip"]
        
        # Start request tracking
        request_id, correlation_id = telemetry.track_request_start(
            method=request_data["method"],
            path=request_data["path"],
            source_ip=source_ip
        )
        
        # Check if IP is already blocked
        if await self._is_ip_blocked(source_ip):
            logger.warning("Blocked IP attempted access", ip=source_ip, path=request_data["path"])
            
            # Get block remaining time
            remaining_time = brute_force_detector.get_block_remaining_time(source_ip)
            
            telemetry.track_request_end(request_id, status.HTTP_429_TOO_MANY_REQUESTS)
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "IP temporarily blocked due to suspicious activity",
                    "retry_after": remaining_time,
                    "blocked_until": (datetime.utcnow() + 
                                    timedelta(seconds=remaining_time)).isoformat()
                },
                headers={"Retry-After": str(remaining_time)}
            )
        
        # Analyze request for threats
        threat_events = await self._analyze_request_threats(request_data)
        
        # Handle detected threats
        if threat_events:
            # Log all threats
            for threat_event in threat_events:
                await self._log_threat_event(threat_event, correlation_id)
                
                # Auto-block if required
                if threat_event.blocked:
                    await self._block_ip(threat_event.source_ip, threat_event)
            
            # Return block response if any threat requires blocking
            blocking_threats = [t for t in threat_events if t.blocked]
            if blocking_threats:
                telemetry.track_request_end(request_id, status.HTTP_403_FORBIDDEN)
                return await self._create_block_response(blocking_threats)
        
        # Process request normally
        response = await call_next(request)
        
        # Track request completion
        telemetry.track_request_end(request_id, response.status_code, len(response.body) if hasattr(response, 'body') else 0)
        
        # Add security headers
        response.headers["X-Defensive-Monitoring"] = "active"
        response.headers["X-Request-Analyzed"] = "true"
        response.headers["X-Correlation-ID"] = correlation_id
        
        return response


class ThreatEventHandler:
    """Handles threat events and coordinates responses"""
    
    def __init__(self):
        self.event_handlers = {
            AttackType.BRUTE_FORCE: self._handle_brute_force,
            AttackType.SUSPICIOUS_PATTERN: self._handle_suspicious_pattern,
            AttackType.AUTH_FAILURE: self._handle_auth_failure,
            AttackType.FLOODING: self._handle_flooding,
            AttackType.SCANNING: self._handle_scanning,
            AttackType.INJECTION_ATTEMPT: self._handle_injection_attempt,
            AttackType.ABNORMAL_PAYLOAD: self._handle_abnormal_payload,
        }
    
    async def handle_threat(self, threat_event: ThreatEvent):
        """Handle threat event based on type"""
        handler = self.event_handlers.get(threat_event.attack_type)
        if handler:
            await handler(threat_event)
    
    async def _handle_brute_force(self, threat_event: ThreatEvent):
        """Handle brute force attack"""
        logger.critical(
            "Brute force attack detected",
            ip=threat_event.source_ip,
            attempts=threat_event.details.get("failed_attempts", 0),
            fingerprint=threat_event.fingerprint
        )
    
    async def _handle_suspicious_pattern(self, threat_event: ThreatEvent):
        """Handle suspicious pattern"""
        logger.warning(
            "Suspicious pattern detected",
            ip=threat_event.source_ip,
            pattern=threat_event.details.get("pattern_name", "unknown"),
            fingerprint=threat_event.fingerprint
        )
    
    async def _handle_auth_failure(self, threat_event: ThreatEvent):
        """Handle authentication failure"""
        logger.info(
            "Authentication failure recorded",
            ip=threat_event.source_ip,
            username=threat_event.details.get("target_username", "unknown"),
            fingerprint=threat_event.fingerprint
        )
    
    async def _handle_flooding(self, threat_event: ThreatEvent):
        """Handle traffic flooding"""
        logger.warning(
            "Traffic flooding detected",
            ip=threat_event.source_ip,
            requests=threat_event.details.get("requests_per_window", 0),
            fingerprint=threat_event.fingerprint
        )
    
    async def _handle_scanning(self, threat_event: ThreatEvent):
        """Handle scanning behavior"""
        logger.info(
            "Scanning behavior detected",
            ip=threat_event.source_ip,
            unique_paths=threat_event.details.get("unique_paths", 0),
            fingerprint=threat_event.fingerprint
        )
    
    async def _handle_injection_attempt(self, threat_event: ThreatEvent):
        """Handle injection attempt"""
        logger.critical(
            "Injection attack attempt detected",
            ip=threat_event.source_ip,
            pattern=threat_event.details.get("pattern_name", "unknown"),
            fingerprint=threat_event.fingerprint
        )
    
    async def _handle_abnormal_payload(self, threat_event: ThreatEvent):
        """Handle abnormal payload"""
        logger.warning(
            "Abnormal payload detected",
            ip=threat_event.source_ip,
            details=threat_event.details,
            fingerprint=threat_event.fingerprint
        )


# Global threat event handler
threat_handler = ThreatEventHandler()


# Utility functions for external usage
async def record_auth_failure(request: Request, username: str = None):
    """Record authentication failure from auth endpoints"""
    middleware = DefensiveMonitoringMiddleware(None)
    await middleware._handle_auth_failure(request, username)


async def is_ip_blocked(source_ip: str) -> bool:
    """Check if IP is blocked"""
    middleware = DefensiveMonitoringMiddleware(None)
    return await middleware._is_ip_blocked(source_ip)


async def get_threat_statistics() -> Dict[str, Any]:
    """Get threat detection statistics"""
    try:
        # This would typically query Redis or a database for statistics
        return {
            "threats_detected_last_hour": 0,
            "ips_blocked_currently": 0,
            "most_common_attack_type": "unknown",
            "top_blocked_ips": []
        }
    except Exception as e:
        logger.error(f"Error getting threat statistics: {e}")
        return {}
