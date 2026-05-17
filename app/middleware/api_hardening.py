"""
MARY V5 SHIELD CORE - API Hardening Middleware
Anti-DDoS, abuse detection, and request validation
"""

import os
import time
import json
import asyncio
import hashlib
import ipaddress
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque
import re

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class ThreatLevel(Enum):
    """API threat levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ViolationType(Enum):
    """API violation types"""
    RATE_LIMIT = "rate_limit"
    REQUEST_SIZE = "request_size"
    MALFORMED_HEADERS = "malformed_headers"
    INVALID_PAYLOAD = "invalid_payload"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    ABUSE_PATTERN = "abuse_pattern"
    DDOS_ATTEMPT = "ddos_attempt"
    BRUTE_FORCE = "brute_force"
    REPLAY_ATTACK = "replay_attack"
    MALFORMED_JSON = "malformed_json"
    CONTENT_TYPE_MISMATCH = "content_type_mismatch"
    REQUEST_FINGERPRINT = "request_fingerprint"


@dataclass
class APIViolation:
    """API violation data structure"""
    id: str
    timestamp: datetime
    violation_type: ViolationType
    threat_level: ThreatLevel
    source_ip: str
    user_agent: str
    endpoint: str
    method: str
    details: Dict[str, Any]
    blocked: bool = False
    mitigation_actions: List[str] = None
    
    def __post_init__(self):
        if self.mitigation_actions is None:
            self.mitigation_actions = []


class RequestValidator:
    """Advanced request validation"""
    
    def __init__(self):
        self.enabled = os.getenv("REQUEST_VALIDATOR_ENABLED", "true").lower() == "true"
        
        # Request size limits
        self.max_request_size = int(os.getenv("MAX_REQUEST_SIZE_MB", "10")) * 1024 * 1024
        self.max_header_size = int(os.getenv("MAX_HEADER_SIZE_KB", "8")) * 1024
        self.max_url_length = int(os.getenv("MAX_URL_LENGTH", "2048"))
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r"<script[^>]*>", r"javascript:", r"eval\(", r"exec\(",
            r"union.*select", r"drop.*table", r"insert.*into",
            r"\.\./", r"\.\.\\", r"%2e%2f", r"file://",
            r"<iframe", r"<object", r"<embed", r"<link"
        ]
        
        # Malformed header patterns
        self.malformed_header_patterns = [
            r"[\x00-\x1F\x7F]",  # Control characters
            r"[\r\n]",  # Newlines in headers
            r"[<>]",  # HTML tags in headers
        ]
        
        logger.info("Request validator initialized", enabled=self.enabled)


class BodySizeEnforcer:
    """Enhanced body size enforcement with content-type specific limits"""
    
    def __init__(self):
        self.enabled = os.getenv("BODY_SIZE_ENFORCER_ENABLED", "true").lower() == "true"
        
        # Content-type specific size limits (in bytes)
        self.content_type_limits = {
            "application/json": int(os.getenv("JSON_MAX_SIZE_MB", "5")) * 1024 * 1024,
            "application/x-www-form-urlencoded": int(os.getenv("FORM_MAX_SIZE_MB", "2")) * 1024 * 1024,
            "multipart/form-data": int(os.getenv("MULTIPART_MAX_SIZE_MB", "20")) * 1024 * 1024,
            "text/plain": int(os.getenv("TEXT_MAX_SIZE_MB", "1")) * 1024 * 1024,
            "application/xml": int(os.getenv("XML_MAX_SIZE_MB", "3")) * 1024 * 1024,
            "text/xml": int(os.getenv("XML_MAX_SIZE_MB", "3")) * 1024 * 1024,
            "application/octet-stream": int(os.getenv("BINARY_MAX_SIZE_MB", "50")) * 1024 * 1024,
            "default": int(os.getenv("DEFAULT_MAX_SIZE_MB", "10")) * 1024 * 1024
        }
        
        logger.info("Body size enforcer initialized", enabled=self.enabled)
    
    def get_content_type_limit(self, content_type: str) -> int:
        """Get size limit for content type"""
        content_type = content_type.lower().split(';')[0].strip()
        
        # Exact match first
        if content_type in self.content_type_limits:
            return self.content_type_limits[content_type]
        
        # Partial match
        for ct, limit in self.content_type_limits.items():
            if content_type.startswith(ct):
                return limit
        
        return self.content_type_limits["default"]
    
    def check_body_size(self, request: Request) -> Optional[APIViolation]:
        """Check request body size"""
        if not self.enabled:
            return None
        
        content_length = request.headers.get("content-length")
        if not content_length:
            return None
        
        try:
            body_size = int(content_length)
            content_type = request.headers.get("content-type", "default")
            size_limit = self.get_content_type_limit(content_type)
            
            if body_size > size_limit:
                return APIViolation(
                    id=f"body_size_{int(time.time() * 1000)}",
                    timestamp=datetime.utcnow(),
                    violation_type=ViolationType.REQUEST_SIZE,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=self._get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    endpoint=request.url.path,
                    method=request.method,
                    details={
                        "violation": "body_size_exceeded",
                        "content_type": content_type,
                        "body_size": body_size,
                        "size_limit": size_limit,
                        "oversize_percentage": round((body_size - size_limit) / size_limit * 100, 2)
                    }
                )
        
        except (ValueError, TypeError):
            pass
        
        return None


class ReplayAttackDetector:
    """Replay attack detection with request fingerprinting"""
    
    def __init__(self):
        self.enabled = os.getenv("REPLAY_ATTACK_DETECTOR_ENABLED", "true").lower() == "true"
        
        # Replay detection window (seconds)
        self.detection_window = int(os.getenv("REPLAY_DETECTION_WINDOW", "300"))  # 5 minutes
        
        # Request fingerprint cache
        self.request_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_cleanup_interval = int(os.getenv("REPLAY_CACHE_CLEANUP_INTERVAL", "60"))  # 1 minute
        
        # Fingerprint components
        self.fingerprint_components = [
            "method",
            "path", 
            "query_params",
            "body_hash",
            "content_type",
            "user_agent"
        ]
        
        logger.info("Replay attack detector initialized", enabled=self.enabled)
    
    def generate_fingerprint(self, request: Request, body: bytes = None) -> str:
        """Generate request fingerprint"""
        components = []
        
        # Method
        components.append(request.method)
        
        # Path
        components.append(request.url.path)
        
        # Query parameters
        query_params = dict(request.query_params)
        components.append(json.dumps(sorted(query_params.items()), sort_keys=True))
        
        # Body hash (if available)
        if body:
            body_hash = hashlib.sha256(body).hexdigest()
            components.append(body_hash)
        
        # Content type
        content_type = request.headers.get("content-type", "")
        components.append(content_type)
        
        # User agent
        user_agent = request.headers.get("user-agent", "")
        components.append(user_agent)
        
        # Create fingerprint
        fingerprint_data = "|".join(components)
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        return fingerprint
    
    def check_replay_attack(self, request: Request, body: bytes = None) -> Optional[APIViolation]:
        """Check for replay attack"""
        if not self.enabled:
            return None
        
        fingerprint = self.generate_fingerprint(request, body)
        current_time = datetime.utcnow()
        
        # Check if fingerprint exists in cache
        if fingerprint in self.request_cache:
            cached_request = self.request_cache[fingerprint]
            
            # Check if within detection window
            time_diff = (current_time - cached_request["timestamp"]).total_seconds()
            if time_diff < self.detection_window:
                return APIViolation(
                    id=f"replay_{int(time.time() * 1000)}",
                    timestamp=current_time,
                    violation_type=ViolationType.REPLAY_ATTACK,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=self._get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    endpoint=request.url.path,
                    method=request.method,
                    details={
                        "fingerprint": fingerprint[:16] + "...",  # Partial fingerprint for logging
                        "original_timestamp": cached_request["timestamp"].isoformat(),
                        "time_diff_seconds": time_diff,
                        "detection_window": self.detection_window
                    }
                )
        
        # Store fingerprint
        self.request_cache[fingerprint] = {
            "timestamp": current_time,
            "source_ip": self._get_client_ip(request),
            "method": request.method,
            "path": request.url.path
        }
        
        return None
    
    def cleanup_cache(self):
        """Clean up old fingerprints"""
        if not self.enabled:
            return
        
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.detection_window)
        expired_fingerprints = [
            fp for fp, data in self.request_cache.items()
            if data["timestamp"] < cutoff_time
        ]
        
        for fp in expired_fingerprints:
            del self.request_cache[fp]
        
        if expired_fingerprints:
            logger.debug(f"Cleaned up {len(expired_fingerprints)} expired fingerprints")


class MalformedJSONDetector:
    """Malformed JSON detection"""
    
    def __init__(self):
        self.enabled = os.getenv("MALFORMED_JSON_DETECTOR_ENABLED", "true").lower() == "true"
        
        logger.info("Malformed JSON detector initialized", enabled=self.enabled)
    
    def check_json_payload(self, request: Request, body: bytes) -> Optional[APIViolation]:
        """Check for malformed JSON"""
        if not self.enabled:
            return None
        
        content_type = request.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            return None
        
        if not body:
            return None
        
        try:
            # Try to parse JSON
            json.loads(body.decode('utf-8'))
        except json.JSONDecodeError as e:
            return APIViolation(
                id=f"json_malformed_{int(time.time() * 1000)}",
                timestamp=datetime.utcnow(),
                violation_type=ViolationType.MALFORMED_JSON,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                endpoint=request.url.path,
                method=request.method,
                details={
                    "error": str(e),
                    "json_size": len(body),
                    "content_type": content_type
                }
            )
        except UnicodeDecodeError as e:
            return APIViolation(
                id=f"json_unicode_{int(time.time() * 1000)}",
                timestamp=datetime.utcnow(),
                violation_type=ViolationType.MALFORMED_JSON,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                endpoint=request.url.path,
                method=request.method,
                details={
                    "error": str(e),
                    "json_size": len(body),
                    "content_type": content_type
                }
            )
        
        return None


class ContentTypeValidator:
    """Content-Type validation"""
    
    def __init__(self):
        self.enabled = os.getenv("CONTENT_TYPE_VALIDATOR_ENABLED", "true").lower() == "true"
        
        # Allowed content types per endpoint
        self.allowed_content_types = {
            "POST": [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "text/plain"
            ],
            "PUT": [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data"
            ],
            "PATCH": [
                "application/json"
            ]
        }
        
        logger.info("Content type validator initialized", enabled=self.enabled)
    
    def validate_content_type(self, request: Request) -> Optional[APIViolation]:
        """Validate content type"""
        if not self.enabled:
            return None
        
        method = request.method
        if method not in self.allowed_content_types:
            return None
        
        content_type = request.headers.get("content-type", "").lower()
        if not content_type:
            return APIViolation(
                id=f"no_content_type_{int(time.time() * 1000)}",
                timestamp=datetime.utcnow(),
                violation_type=ViolationType.CONTENT_TYPE_MISMATCH,
                threat_level=ThreatLevel.LOW,
                source_ip=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                endpoint=request.url.path,
                method=method,
                details={
                    "violation": "missing_content_type",
                    "allowed_types": self.allowed_content_types[method]
                }
            )
        
        # Extract main content type (ignore charset etc.)
        main_content_type = content_type.split(';')[0].strip()
        
        if main_content_type not in self.allowed_content_types[method]:
            return APIViolation(
                id=f"invalid_content_type_{int(time.time() * 1000)}",
                timestamp=datetime.utcnow(),
                violation_type=ViolationType.CONTENT_TYPE_MISMATCH,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=self._get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                endpoint=request.url.path,
                method=method,
                details={
                    "violation": "invalid_content_type",
                    "content_type": main_content_type,
                    "allowed_types": self.allowed_content_types[method]
                }
            )
        
        return None


def _get_client_ip(request: Request) -> str:
    """Get client IP address"""
    # Check for forwarded headers
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to client IP
    return request.client.host if request.client else "unknown"
    
    def _check_headers(self, request: Request) -> List[APIViolation]:
        """Check for malformed headers"""
        violations = []
        
        for header_name, header_value in request.headers.items():
            # Check header size
            if len(header_value) > self.max_header_size:
                violations.append(APIViolation(
                    id=f"header_size_{int(time.time() * 1000)}_{len(violations)}",
                    timestamp=datetime.utcnow(),
                    violation_type=ViolationType.MALFORMED_HEADERS,
                    threat_level=ThreatLevel.LOW,
                    source_ip=self._get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    endpoint=request.url.path,
                    method=request.method,
                    details={
                        "violation": "header_too_large",
                        "header_name": header_name,
                        "header_size": len(header_value),
                        "max_allowed": self.max_header_size
                    }
                ))
            
            # Check for malformed patterns
            for pattern in self.malformed_header_patterns:
                if re.search(pattern, header_value):
                    violations.append(APIViolation(
                        id=f"header_malformed_{int(time.time() * 1000)}_{len(violations)}",
                        timestamp=datetime.utcnow(),
                        violation_type=ViolationType.MALFORMED_HEADERS,
                        threat_level=ThreatLevel.MEDIUM,
                        source_ip=self._get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        endpoint=request.url.path,
                        method=request.method,
                        details={
                            "violation": "malformed_header_pattern",
                            "header_name": header_name,
                            "pattern": pattern,
                            "header_value": header_value[:100]  # Limit length
                        }
                    ))
        
        return violations
    
    def _check_url(self, request: Request) -> Optional[APIViolation]:
        """Check URL for suspicious patterns"""
        url_str = str(request.url)
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url_str, re.IGNORECASE):
                return APIViolation(
                    id=f"url_suspicious_{int(time.time() * 1000)}",
                    timestamp=datetime.utcnow(),
                    violation_type=ViolationType.SUSPICIOUS_PATTERN,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=self._get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    endpoint=request.url.path,
                    method=request.method,
                    details={
                        "violation": "suspicious_url_pattern",
                        "pattern": pattern,
                        "url": url_str[:200]  # Limit length
                    }
                )
        
        return None
    
    def _check_query_params(self, request: Request) -> List[APIViolation]:
        """Check query parameters for suspicious patterns"""
        violations = []
        
        for param_name, param_value in request.query_params.items():
            for pattern in self.suspicious_patterns:
                if re.search(pattern, param_value, re.IGNORECASE):
                    violations.append(APIViolation(
                        id=f"query_suspicious_{int(time.time() * 1000)}_{len(violations)}",
                        timestamp=datetime.utcnow(),
                        violation_type=ViolationType.SUSPICIOUS_PATTERN,
                        threat_level=ThreatLevel.HIGH,
                        source_ip=self._get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        endpoint=request.url.path,
                        method=request.method,
                        details={
                            "violation": "suspicious_query_pattern",
                            "parameter": param_name,
                            "pattern": pattern,
                            "value": param_value[:100]  # Limit length
                        }
                    ))
        
        return violations
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check for proxy headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"


class DDoSProtection:
    """Advanced DDoS protection and rate limiting"""
    
    def __init__(self):
        self.enabled = os.getenv("DDOS_PROTECTION_ENABLED", "true").lower() == "true"
        
        # Rate limiting configuration
        self.global_rps = int(os.getenv("GLOBAL_RPS", "100"))  # Requests per second
        self.ip_rps = int(os.getenv("IP_RPS", "10"))  # Requests per second per IP
        self.burst_allowance = int(os.getenv("BURST_ALLOWANCE", "5"))
        
        # DDoS detection thresholds
        self.ddos_threshold = int(os.getenv("DDOS_THRESHOLD", "1000"))  # Requests per minute
        self.block_duration = int(os.getenv("DDOS_BLOCK_DURATION", "300"))  # 5 minutes
        
        # Tracking storage
        self.global_requests = deque(maxlen=self.global_rps * 60)
        self.ip_requests = defaultdict(lambda: deque(maxlen=self.ip_rps * 60))
        self.blocked_ips = {}
        
        # Statistics
        self.ddos_stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "currently_blocked": 0,
            "ddos_attempts": 0
        }
        
        logger.info("DDoS protection initialized", enabled=self.enabled)
    
    def check_request(self, request: Request) -> Optional[APIViolation]:
        """Check request for DDoS patterns"""
        if not self.enabled:
            return None
        
        client_ip = self._get_client_ip(request)
        current_time = time.time()
        
        # Check if IP is blocked
        if self._is_ip_blocked(client_ip):
            self.ddos_stats["blocked_requests"] += 1
            return APIViolation(
                id=f"ddos_blocked_{int(current_time * 1000)}",
                timestamp=datetime.utcnow(),
                violation_type=ViolationType.DDOS_ATTEMPT,
                threat_level=ThreatLevel.CRITICAL,
                source_ip=client_ip,
                user_agent=request.headers.get("user-agent", ""),
                endpoint=request.url.path,
                method=request.method,
                details={
                    "violation": "ip_blocked_ddos",
                    "block_remaining": self.blocked_ips[client_ip] - current_time if client_ip in self.blocked_ips else 0
                },
                blocked=True
            )
        
        # Track request
        self.global_requests.append(current_time)
        self.ip_requests[client_ip].append(current_time)
        self.ddos_stats["total_requests"] += 1
        
        # Clean old requests
        self._cleanup_old_requests(current_time)
        
        # Check for DDoS patterns
        ddos_violation = self._check_ddos_patterns(client_ip, current_time)
        if ddos_violation:
            self.ddos_stats["ddos_attempts"] += 1
            return ddos_violation
        
        # Check rate limits
        rate_violation = self._check_rate_limits(client_ip, current_time)
        if rate_violation:
            return rate_violation
        
        return None
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        if ip not in self.blocked_ips:
            return False
        
        # Check if block has expired
        if time.time() > self.blocked_ips[ip]:
            del self.blocked_ips[ip]
            self.ddos_stats["currently_blocked"] -= 1
            return False
        
        return True
    
    def _cleanup_old_requests(self, current_time: float):
        """Clean up old request records"""
        cutoff_time = current_time - 60  # 1 minute ago
        
        # Clean global requests
        while self.global_requests and self.global_requests[0] < cutoff_time:
            self.global_requests.popleft()
        
        # Clean IP requests
        for ip in list(self.ip_requests.keys()):
            while self.ip_requests[ip] and self.ip_requests[ip][0] < cutoff_time:
                self.ip_requests[ip].popleft()
            
            # Remove empty IP entries
            if not self.ip_requests[ip]:
                del self.ip_requests[ip]
    
    def _check_ddos_patterns(self, ip: str, current_time: float) -> Optional[APIViolation]:
        """Check for DDoS attack patterns"""
        # Check global request rate
        recent_global = len(self.global_requests)
        if recent_global > self.ddos_threshold:
            # Block the source IP for DDoS
            self._block_ip(ip, current_time)
            
            return APIViolation(
                id=f"ddos_global_{int(current_time * 1000)}",
                timestamp=datetime.utcnow(),
                violation_type=ViolationType.DDOS_ATTEMPT,
                threat_level=ThreatLevel.CRITICAL,
                source_ip=ip,
                user_agent="",  # Will be set by caller
                endpoint="",  # Will be set by caller
                method="",   # Will be set by caller
                details={
                    "violation": "global_ddos_threshold",
                    "global_rps": recent_global,
                    "threshold": self.ddos_threshold
                },
                blocked=True
            )
        
        # Check per-IP request rate
        if ip in self.ip_requests:
            recent_ip = len(self.ip_requests[ip])
            if recent_ip > self.ddos_threshold // 10:  # 10% of global threshold
                self._block_ip(ip, current_time)
                
                return APIViolation(
                    id=f"ddos_ip_{int(current_time * 1000)}",
                    timestamp=datetime.utcnow(),
                    violation_type=ViolationType.DDOS_ATTEMPT,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=ip,
                    user_agent="",  # Will be set by caller
                    endpoint="",  # Will be set by caller
                    method="",   # Will be set by caller
                    details={
                        "violation": "ip_ddos_threshold",
                        "ip_rps": recent_ip,
                        "threshold": self.ddos_threshold // 10
                    },
                    blocked=True
                )
        
        return None
    
    def _check_rate_limits(self, ip: str, current_time: float) -> Optional[APIViolation]:
        """Check rate limits"""
        if ip not in self.ip_requests:
            return None
        
        recent_requests = len(self.ip_requests[ip])
        
        # Check IP rate limit
        if recent_requests > self.ip_rps:
            return APIViolation(
                id=f"rate_limit_{int(current_time * 1000)}",
                timestamp=datetime.utcnow(),
                violation_type=ViolationType.RATE_LIMIT,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=ip,
                user_agent="",  # Will be set by caller
                endpoint="",  # Will be set by caller
                method="",   # Will be set by caller
                details={
                    "violation": "ip_rate_limit",
                    "requests_per_second": recent_requests,
                    "limit": self.ip_rps
                }
            )
        
        return None
    
    def _block_ip(self, ip: str, current_time: float):
        """Block IP address"""
        self.blocked_ips[ip] = current_time + self.block_duration
        self.ddos_stats["currently_blocked"] += 1
        
        logger.warning(f"IP blocked due to DDoS detection", ip=ip, duration=self.block_duration)
        
        log_security_event(
            "ip_blocked_ddos",
            {
                "ip": ip,
                "block_duration": self.block_duration,
                "blocked_until": datetime.fromtimestamp(current_time + self.block_duration).isoformat()
            }
        )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def get_ddos_stats(self) -> Dict[str, Any]:
        """Get DDoS protection statistics"""
        return {
            "enabled": self.enabled,
            **self.ddos_stats,
            "configuration": {
                "global_rps": self.global_rps,
                "ip_rps": self.ip_rps,
                "ddos_threshold": self.ddos_threshold,
                "block_duration": self.block_duration
            },
            "current_metrics": {
                "global_requests_per_minute": len(self.global_requests),
                "active_ips": len(self.ip_requests),
                "blocked_ips": len(self.blocked_ips)
            }
        }


class AbuseDetector:
    """Advanced abuse pattern detection"""
    
    def __init__(self):
        self.enabled = os.getenv("ABUSE_DETECTOR_ENABLED", "true").lower() == "true"
        
        # Abuse patterns
        self.abuse_patterns = {
            "brute_force": {
                "threshold": 10,  # Failed attempts
                "window": 300,   # 5 minutes
                "endpoints": ["/api/v1/auth/login", "/api/v1/auth/token"],
                "methods": ["POST"]
            },
            "api_scraping": {
                "threshold": 100,  # Requests
                "window": 60,     # 1 minute
                "endpoints": ["/api/v1/users", "/api/v1/data"],
                "methods": ["GET"]
            },
            "endpoint_abuse": {
                "threshold": 50,   # Requests
                "window": 60,     # 1 minute
                "endpoints": ["*"],  # All endpoints
                "methods": ["*"]   # All methods
            }
        }
        
        # Tracking storage
        self.abuse_tracking = defaultdict(lambda: defaultdict(list))
        self.blocked_abusers = {}
        
        # Statistics
        self.abuse_stats = {
            "abuse_attempts": 0,
            "blocked_abusers": 0,
            "patterns_detected": defaultdict(int)
        }
        
        logger.info("Abuse detector initialized", enabled=self.enabled)
    
    def detect_abuse(self, request: Request, user_id: str = None) -> List[APIViolation]:
        """Detect abuse patterns"""
        if not self.enabled:
            return []
        
        violations = []
        client_ip = self._get_client_ip(request)
        current_time = time.time()
        endpoint = request.url.path
        method = request.method
        
        # Track request
        identifier = user_id or client_ip
        self.abuse_tracking[identifier]["all"].append(current_time)
        self.abuse_tracking[identifier][f"{method}:{endpoint}"].append(current_time)
        
        # Check abuse patterns
        for pattern_name, pattern_config in self.abuse_patterns.items():
            violation = self._check_abuse_pattern(
                identifier, pattern_name, pattern_config, 
                endpoint, method, current_time
            )
            if violation:
                violations.append(violation)
                self.abuse_stats["abuse_attempts"] += 1
                self.abuse_stats["patterns_detected"][pattern_name] += 1
        
        return violations
    
    def _check_abuse_pattern(self, identifier: str, pattern_name: str, 
                           pattern_config: Dict, endpoint: str, method: str, 
                           current_time: float) -> Optional[APIViolation]:
        """Check specific abuse pattern"""
        # Check if endpoint/method matches pattern
        endpoints = pattern_config["endpoints"]
        methods = pattern_config["methods"]
        
        if "*" not in endpoints and endpoint not in endpoints:
            return None
        if "*" not in methods and method not in methods:
            return None
        
        # Get relevant tracking key
        if "*" in endpoints and "*" in methods:
            tracking_key = "all"
        elif "*" in endpoints:
            tracking_key = f"{method}:*"
        elif "*" in methods:
            tracking_key = f"*:{endpoint}"
        else:
            tracking_key = f"{method}:{endpoint}"
        
        # Check request count in window
        if tracking_key in self.abuse_tracking[identifier]:
            requests = self.abuse_tracking[identifier][tracking_key]
            window_start = current_time - pattern_config["window"]
            
            recent_requests = [req_time for req_time in requests if req_time > window_start]
            
            if len(recent_requests) >= pattern_config["threshold"]:
                # Block the abuser
                self._block_abuser(identifier, current_time)
                
                return APIViolation(
                    id=f"abuse_{pattern_name}_{int(current_time * 1000)}",
                    timestamp=datetime.utcnow(),
                    violation_type=ViolationType.ABUSE_PATTERN,
                    threat_level=ThreatLevel.HIGH,
                    source_ip=self._get_client_ip_from_identifier(identifier),
                    user_agent="",  # Will be set by caller
                    endpoint=endpoint,
                    method=method,
                    details={
                        "violation": f"abuse_pattern_{pattern_name}",
                        "pattern_name": pattern_name,
                        "request_count": len(recent_requests),
                        "threshold": pattern_config["threshold"],
                        "window": pattern_config["window"],
                        "identifier": identifier
                    },
                    blocked=True
                )
        
        return None
    
    def _block_abuser(self, identifier: str, current_time: float):
        """Block abuser"""
        block_duration = 3600  # 1 hour
        self.blocked_abusers[identifier] = current_time + block_duration
        self.abuse_stats["blocked_abusers"] += 1
        
        logger.warning(f"Abuser blocked due to pattern detection", identifier=identifier, duration=block_duration)
        
        log_security_event(
            "abuser_blocked",
            {
                "identifier": identifier,
                "block_duration": block_duration,
                "blocked_until": datetime.fromtimestamp(current_time + block_duration).isoformat()
            }
        )
    
    def _get_client_ip_from_identifier(self, identifier: str) -> str:
        """Extract IP from identifier"""
        # If identifier looks like an IP address, return it
        try:
            ipaddress.ip_address(identifier)
            return identifier
        except ValueError:
            return "unknown"
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def get_abuse_stats(self) -> Dict[str, Any]:
        """Get abuse detection statistics"""
        return {
            "enabled": self.enabled,
            **self.abuse_stats,
            "configuration": self.abuse_patterns,
            "current_metrics": {
                "tracked_identifiers": len(self.abuse_tracking),
                "blocked_abusers": len(self.blocked_abusers)
            }
        }


class APIHardeningMiddleware(BaseHTTPMiddleware):
    """Main API hardening middleware"""
    
    def __init__(self, app):
        super().__init__(app)
        self.enabled = os.getenv("API_HARDENING_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.request_validator = RequestValidator()
        self.ddos_protection = DDoSProtection()
        self.abuse_detector = AbuseDetector()
        
        # Middleware statistics
        self.middleware_stats = {
            "requests_processed": 0,
            "violations_detected": 0,
            "requests_blocked": 0,
            "violations_by_type": defaultdict(int)
        }
        
        logger.info("API hardening middleware initialized", enabled=self.enabled)
    
    async def dispatch(self, request: Request, call_next):
        """Process request through hardening pipeline"""
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        violations = []
        
        try:
            # Get user ID from request state if available
            user_id = getattr(request.state, "user_id", None)
            
            # Request validation
            validation_violations = self.request_validator.validate_request(request)
            violations.extend(validation_violations)
            
            # DDoS protection
            ddos_violation = self.ddos_protection.check_request(request)
            if ddos_violation:
                violations.append(ddos_violation)
            
            # Abuse detection
            abuse_violations = self.abuse_detector.detect_abuse(request, user_id)
            violations.extend(abuse_violations)
            
            # Update statistics
            self.middleware_stats["requests_processed"] += 1
            for violation in violations:
                self.middleware_stats["violations_detected"] += 1
                self.middleware_stats["violations_by_type"][violation.violation_type.value] += 1
                
                if violation.blocked:
                    self.middleware_stats["requests_blocked"] += 1
            
            # Handle violations
            if violations:
                await self._handle_violations(request, violations)
            
            # Block request if any violation is blocking
            blocking_violations = [v for v in violations if v.blocked]
            if blocking_violations:
                return self._create_block_response(blocking_violations[0])
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response, violations)
            
            # Log request completion
            duration = (time.time() - start_time) * 1000
            await self._log_request_completion(request, response, violations, duration)
            
            return response
            
        except Exception as e:
            logger.error("API hardening middleware error", error=str(e))
            return await call_next(request)
    
    async def _handle_violations(self, request: Request, violations: List[APIViolation]):
        """Handle detected violations"""
        for violation in violations:
            # Update violation with request context
            violation.user_agent = request.headers.get("user-agent", "")
            violation.endpoint = request.url.path
            violation.method = request.method
            
            # Log violation
            log_security_event(
                "api_violation_detected",
                {
                    "violation_id": violation.id,
                    "violation_type": violation.violation_type.value,
                    "threat_level": violation.threat_level.value,
                    "source_ip": violation.source_ip,
                    "endpoint": violation.endpoint,
                    "method": violation.method,
                    "blocked": violation.blocked,
                    "details": violation.details
                }
            )
    
    def _create_block_response(self, violation: APIViolation) -> Response:
        """Create blocking response"""
        response = JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": "Request blocked",
                "violation_type": violation.violation_type.value,
                "threat_level": violation.threat_level.value,
                "message": "Your request has been blocked due to suspicious activity"
            }
        )
        
        # Add security headers
        response.headers["X-Violation-Type"] = violation.violation_type.value
        response.headers["X-Threat-Level"] = violation.threat_level.value
        response.headers["X-Blocked"] = "true"
        
        return response
    
    def _add_security_headers(self, response: Response, violations: List[APIViolation]):
        """Add security headers to response"""
        if violations:
            max_threat = max(violations, key=lambda v: list(ThreatLevel).index(v.threat_level))
            response.headers["X-Max-Threat-Level"] = max_threat.threat_level.value
            response.headers["X-Violation-Count"] = str(len(violations))
        
        response.headers["X-API-Protection"] = "active"
        response.headers["X-Request-Validated"] = "true"
    
    async def _log_request_completion(self, request: Request, response: Response, 
                                    violations: List[APIViolation], duration: float):
        """Log request completion"""
        log_audit_event(
            "api_request_completed",
            user=getattr(request.state, "user_id", None),
            resource=f"{request.method} {request.url.path}",
            result="success" if response.status_code < 400 else "error",
            details={
                "duration_ms": round(duration, 2),
                "status_code": response.status_code,
                "violations_count": len(violations),
                "violations_blocked": len([v for v in violations if v.blocked])
            }
        )
    
    def get_middleware_stats(self) -> Dict[str, Any]:
        """Get middleware statistics"""
        return {
            "enabled": self.enabled,
            **self.middleware_stats,
            "components": {
                "request_validator": self.request_validator.enabled,
                "ddos_protection": self.ddos_protection.enabled,
                "abuse_detector": self.abuse_detector.enabled
            },
            "ddos_stats": self.ddos_protection.get_ddos_stats(),
            "abuse_stats": self.abuse_detector.get_abuse_stats()
        }


# Global middleware instance
api_hardening_middleware = None


def get_api_hardening_middleware(app):
    """Get API hardening middleware instance"""
    global api_hardening_middleware
    if api_hardening_middleware is None:
        api_hardening_middleware = APIHardeningMiddleware(app)
    return api_hardening_middleware


def get_api_hardening_stats() -> Dict[str, Any]:
    """Get API hardening statistics"""
    if api_hardening_middleware:
        return api_hardening_middleware.get_middleware_stats()
    return {"enabled": False}
