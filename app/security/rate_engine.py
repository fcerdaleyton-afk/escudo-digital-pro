"""
MARY V5 SHIELD CORE - Security Rate Engine
Adaptive rate limiting with IP scoring, burst detection, and progressive penalties
"""

import os
import time
import asyncio
import hashlib
import json
import ipaddress
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import threading
import weakref

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger
from app.core.security_settings import get_security_settings


class RiskLevel(Enum):
    """IP risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"


class ViolationType(Enum):
    """Rate limiting violation types"""
    RATE_LIMIT = "rate_limit"
    BURST_DETECTED = "burst_detected"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    IP_REPUTATION = "ip_reputation"
    ABUSE_PATTERN = "abuse_pattern"
    QUARANTINE = "quarantine"


@dataclass
class IPReputation:
    """IP reputation data"""
    ip_address: str
    risk_level: RiskLevel = RiskLevel.LOW
    score: float = 0.0
    violations: List[ViolationType] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    request_count: int = 0
    blocked_until: Optional[datetime] = None
    quarantine_until: Optional[datetime] = None
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        if self.blocked_until:
            data['blocked_until'] = self.blocked_until.isoformat()
        if self.quarantine_until:
            data['quarantine_until'] = self.quarantine_until.isoformat()
        data['risk_level'] = self.risk_level.value
        return data


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    name: str
    requests_per_second: float = 10.0
    burst_size: int = 20
    window_size: int = 60  # seconds
    penalty_factor: float = 2.0
    adaptive_enabled: bool = True
    ip_scoring_enabled: bool = True
    quarantine_enabled: bool = True
    progressive_penalties: bool = True
    fingerprint_enabled: bool = True


@dataclass
class RateLimitResult:
    """Rate limiting result"""
    allowed: bool
    remaining_requests: int
    reset_time: datetime
    violation_type: Optional[ViolationType] = None
    penalty_applied: bool = False
    quarantine_applied: bool = False
    block_applied: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    metadata: Dict[str, Any] = field(default_factory=dict)


class ClientFingerprint:
    """Client fingerprinting for detection"""
    
    def __init__(self):
        self.enabled = os.getenv("CLIENT_FINGERPRINTING_ENABLED", "true").lower() == "true"
        self.logger = get_structured_logger("client_fingerprint")
    
    def generate_fingerprint(self, request_data: Dict[str, Any]) -> str:
        """Generate client fingerprint from request data"""
        if not self.enabled:
            return ""
        
        try:
            # Extract fingerprint components
            components = []
            
            # User-Agent (normalized)
            user_agent = request_data.get("user_agent", "").lower()
            if user_agent:
                # Normalize common variations
                user_agent = user_agent.replace(" ", "")
                user_agent = user_agent.replace("/", "_")
                components.append(f"ua:{user_agent}")
            
            # Accept-Language
            accept_lang = request_data.get("accept_language", "").lower()
            if accept_lang:
                components.append(f"lang:{accept_lang.split(',')[0]}")
            
            # Accept-Encoding
            accept_enc = request_data.get("accept_encoding", "").lower()
            if accept_enc:
                components.append(f"enc:{accept_enc}")
            
            # HTTP Version
            http_version = request_data.get("http_version", "")
            if http_version:
                components.append(f"http:{http_version}")
            
            # Request headers pattern
            headers = request_data.get("headers", {})
            header_count = len(headers)
            header_names = sorted(headers.keys())
            header_pattern = hashlib.md5("|".join(header_names).encode()).hexdigest()[:8]
            components.append(f"headers:{header_count}:{header_pattern}")
            
            # Create fingerprint
            fingerprint_data = "|".join(components)
            fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
            
            return fingerprint
            
        except Exception as e:
            self.logger.error("Failed to generate fingerprint", error=str(e))
            return ""
    
    def is_suspicious(self, fingerprint: str, request_data: Dict[str, Any]) -> bool:
        """Check if fingerprint indicates suspicious client"""
        if not self.enabled or not fingerprint:
            return False
        
        suspicious_patterns = [
            "curl", "wget", "python-requests", "bot", "crawler",
            "scanner", "exploit", "hack", "attack", "malware"
        ]
        
        user_agent = request_data.get("user_agent", "").lower()
        
        # Check for suspicious user agents
        for pattern in suspicious_patterns:
            if pattern in user_agent:
                return True
        
        # Check for missing common headers
        headers = request_data.get("headers", {})
        if len(headers) < 3:  # Very few headers might indicate automated client
            return True
        
        return False


class IPScoringEngine:
    """IP scoring and reputation engine"""
    
    def __init__(self):
        self.enabled = os.getenv("IP_SCORING_ENABLED", "true").lower() == "true"
        
        # Scoring factors
        self.scoring_weights = {
            "request_frequency": 0.3,
            "violation_count": 0.4,
            "time_since_first_seen": 0.1,
            "geographic_risk": 0.1,
            "fingerprint_risk": 0.1
        }
        
        # Risk thresholds
        self.risk_thresholds = {
            RiskLevel.LOW: 0.2,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.7,
            RiskLevel.CRITICAL: 0.9
        }
        
        # IP reputation storage
        self.ip_reputations: Dict[str, IPReputation] = {}
        self._lock = threading.RLock()
        
        # Cleanup
        self.cleanup_interval = int(os.getenv("IP_CLEANUP_INTERVAL", "3600"))  # 1 hour
        self.max_age = timedelta(days=30)
        
        self.logger = get_structured_logger("ip_scoring")
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_task())
        
        self.logger.info("IP scoring engine initialized", enabled=self.enabled)
    
    def get_ip_reputation(self, ip_address: str) -> IPReputation:
        """Get or create IP reputation"""
        with self._lock:
            if ip_address not in self.ip_reputations:
                self.ip_reputations[ip_address] = IPReputation(ip_address=ip_address)
            
            reputation = self.ip_reputations[ip_address]
            reputation.last_seen = datetime.utcnow()
            
            return reputation
    
    def update_ip_score(self, ip_address: str, request_data: Dict[str, Any], 
                       violation: Optional[ViolationType] = None):
        """Update IP score based on request and violations"""
        if not self.enabled:
            return
        
        reputation = self.get_ip_reputation(ip_address)
        reputation.request_count += 1
        
        # Add violation if provided
        if violation and violation not in reputation.violations:
            reputation.violations.append(violation)
        
        # Update fingerprint
        if request_data.get("fingerprint"):
            reputation.fingerprint = request_data["fingerprint"]
        
        # Calculate new score
        new_score = self._calculate_score(reputation, request_data)
        reputation.score = new_score
        
        # Update risk level
        old_risk_level = reputation.risk_level
        reputation.risk_level = self._determine_risk_level(new_score)
        
        # Log significant changes
        if old_risk_level != reputation.risk_level:
            self.logger.info(
                "IP risk level changed",
                ip=ip_address,
                old_level=old_risk_level.value,
                new_level=reputation.risk_level.value,
                score=round(new_score, 3)
            )
    
    def _calculate_score(self, reputation: IPReputation, request_data: Dict[str, Any]) -> float:
        """Calculate IP risk score"""
        score = 0.0
        
        # Request frequency factor
        time_window = timedelta(hours=1)
        recent_requests = reputation.request_count  # Simplified - in production, track time-based requests
        frequency_score = min(recent_requests / 100, 1.0)  # Normalize to 0-1
        score += frequency_score * self.scoring_weights["request_frequency"]
        
        # Violation count factor
        violation_score = len(reputation.violations) / 10.0  # Normalize
        score += min(violation_score, 1.0) * self.scoring_weights["violation_count"]
        
        # Time since first seen (newer IPs are riskier)
        time_since_first = datetime.utcnow() - reputation.first_seen
        time_score = max(0, 1.0 - (time_since_first.total_seconds() / (30 * 24 * 3600)))  # 30 days
        score += time_score * self.scoring_weights["time_since_first_seen"]
        
        # Geographic risk (simplified)
        if self._is_suspicious_geolocation(reputation.ip_address):
            score += 0.3 * self.scoring_weights["geographic_risk"]
        
        # Fingerprint risk
        if reputation.fingerprint and self._is_suspicious_fingerprint(reputation.fingerprint):
            score += 0.5 * self.scoring_weights["fingerprint_risk"]
        
        return min(score, 1.0)
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        for level, threshold in sorted(self.risk_thresholds.items(), key=lambda x: x[1], reverse=True):
            if score >= threshold:
                return level
        return RiskLevel.LOW
    
    def _is_suspicious_geolocation(self, ip_address: str) -> bool:
        """Check if IP is from suspicious geolocation"""
        # Simplified - in production, use GeoIP database
        suspicious_ranges = [
            "0.0.0.0/8",      # Reserved
            "127.0.0.0/8",    # Loopback
            "169.254.0.0/16", # Link-local
            "224.0.0.0/4",    # Multicast
        ]
        
        try:
            ip = ipaddress.ip_address(ip_address)
            for range_str in suspicious_ranges:
                network = ipaddress.ip_network(range_str)
                if ip in network:
                    return True
        except ValueError:
            pass
        
        return False
    
    def _is_suspicious_fingerprint(self, fingerprint: str) -> bool:
        """Check if fingerprint is suspicious"""
        # In production, maintain a database of known suspicious fingerprints
        suspicious_patterns = [
            "0000000000000000",  # Empty/default
            "ffffffffffffffff",  # All ones
        ]
        
        return fingerprint in suspicious_patterns
    
    def apply_penalty(self, ip_address: str, violation: ViolationType, penalty_factor: float = 2.0):
        """Apply penalty to IP"""
        reputation = self.get_ip_reputation(ip_address)
        
        # Increase score based on penalty
        reputation.score = min(reputation.score * penalty_factor, 1.0)
        reputation.risk_level = self._determine_risk_level(reputation.score)
        
        # Add violation
        if violation not in reputation.violations:
            reputation.violations.append(violation)
        
        self.logger.warning(
            "IP penalty applied",
            ip=ip_address,
            violation=violation.value,
            penalty_factor=penalty_factor,
            new_score=round(reputation.score, 3),
            new_risk_level=reputation.risk_level.value
        )
    
    def quarantine_ip(self, ip_address: str, duration: timedelta):
        """Quarantine IP for specified duration"""
        reputation = self.get_ip_reputation(ip_address)
        reputation.quarantine_until = datetime.utcnow() + duration
        reputation.risk_level = RiskLevel.CRITICAL
        
        self.logger.warning(
            "IP quarantined",
            ip=ip_address,
            duration_seconds=duration.total_seconds(),
            until=reputation.quarantine_until.isoformat()
        )
    
    def block_ip(self, ip_address: str, duration: timedelta):
        """Block IP for specified duration"""
        reputation = self.get_ip_reputation(ip_address)
        reputation.blocked_until = datetime.utcnow() + duration
        reputation.risk_level = RiskLevel.BLOCKED
        
        self.logger.warning(
            "IP blocked",
            ip=ip_address,
            duration_seconds=duration.total_seconds(),
            until=reputation.blocked_until.isoformat()
        )
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is currently blocked"""
        reputation = self.get_ip_reputation(ip_address)
        
        if reputation.blocked_until and datetime.utcnow() < reputation.blocked_until:
            return True
        
        if reputation.quarantine_until and datetime.utcnow() < reputation.quarantine_until:
            return True
        
        return False
    
    async def _cleanup_task(self):
        """Cleanup old IP reputations"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                self._cleanup_old_reputations()
            except Exception as e:
                self.logger.error("IP cleanup task error", error=str(e))
    
    def _cleanup_old_reputations(self):
        """Clean up old IP reputations"""
        with self._lock:
            cutoff_time = datetime.utcnow() - self.max_age
            expired_ips = [
                ip for ip, rep in self.ip_reputations.items()
                if rep.last_seen < cutoff_time and rep.risk_level == RiskLevel.LOW
            ]
            
            for ip in expired_ips:
                del self.ip_reputations[ip]
            
            if expired_ips:
                self.logger.info(f"Cleaned up {len(expired_ips)} old IP reputations")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get IP scoring statistics"""
        with self._lock:
            total_ips = len(self.ip_reputations)
            risk_distribution = defaultdict(int)
            violation_distribution = defaultdict(int)
            
            for reputation in self.ip_reputations.values():
                risk_distribution[reputation.risk_level.value] += 1
                
                for violation in reputation.violations:
                    violation_distribution[violation.value] += 1
            
            return {
                "enabled": self.enabled,
                "total_ips": total_ips,
                "risk_distribution": dict(risk_distribution),
                "violation_distribution": dict(violation_distribution),
                "scoring_weights": self.scoring_weights
            }


class RateLimiter:
    """Adaptive rate limiter with burst detection"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.enabled = os.getenv("RATE_LIMITING_ENABLED", "true").lower() == "true"
        
        # Request tracking
        self.request_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=config.window_size))
        self.burst_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=config.burst_size))
        
        # Adaptive parameters
        self.adaptive_limits: Dict[str, float] = {}
        self.burst_thresholds: Dict[str, int] = {}
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        # Components
        self.ip_scoring = ip_scoring_engine
        self.fingerprinting = ClientFingerprint()
        
        self.logger = get_structured_logger(f"rate_limiter.{config.name}")
        
        self.logger.info("Rate limiter initialized", 
                        name=config.name,
                        rps=config.requests_per_second,
                        burst_size=config.burst_size)
    
    async def check_rate_limit(self, identifier: str, request_data: Dict[str, Any]) -> RateLimitResult:
        """Check rate limit for identifier"""
        if not self.enabled:
            return RateLimitResult(
                allowed=True,
                remaining_requests=999999,
                reset_time=datetime.utcnow() + timedelta(seconds=self.config.window_size)
            )
        
        with self._lock:
            current_time = time.time()
            
            # Generate fingerprint if enabled
            fingerprint = ""
            if self.config.fingerprint_enabled:
                fingerprint = self.fingerprinting.generate_fingerprint(request_data)
                request_data["fingerprint"] = fingerprint
            
            # Update IP scoring
            ip_address = request_data.get("ip_address", "")
            if ip_address and self.config.ip_scoring_enabled:
                self.ip_scoring.update_ip_score(ip_address, request_data)
            
            # Check if IP is blocked
            if ip_address and self.ip_scoring.is_ip_blocked(ip_address):
                return RateLimitResult(
                    allowed=False,
                    remaining_requests=0,
                    reset_time=datetime.utcnow() + timedelta(days=1),
                    violation_type=ViolationType.QUARANTINE,
                    block_applied=True,
                    risk_level=RiskLevel.BLOCKED
                )
            
            # Get adaptive limit
            adaptive_limit = self._get_adaptive_limit(identifier, request_data)
            
            # Check rate limit
            request_window = self.request_windows[identifier]
            request_window.append(current_time)
            
            # Remove old requests outside window
            cutoff_time = current_time - self.config.window_size
            while request_window and request_window[0] < cutoff_time:
                request_window.popleft()
            
            # Check burst
            burst_detected = self._check_burst(identifier, current_time, request_data)
            
            # Apply penalties if needed
            violation_type = None
            penalty_applied = False
            
            if burst_detected:
                violation_type = ViolationType.BURST_DETECTED
                penalty_applied = self._apply_penalty(identifier, request_data, violation_type)
            
            # Check if limit exceeded
            requests_in_window = len(request_window)
            allowed = requests_in_window <= adaptive_limit
            
            if not allowed:
                violation_type = ViolationType.RATE_LIMIT
                penalty_applied = self._apply_penalty(identifier, request_data, violation_type)
            
            # Calculate remaining requests and reset time
            remaining_requests = max(0, int(adaptive_limit - requests_in_window))
            reset_time = datetime.utcnow() + timedelta(seconds=self.config.window_size)
            
            # Get risk level
            risk_level = RiskLevel.LOW
            if ip_address:
                reputation = self.ip_scoring.get_ip_reputation(ip_address)
                risk_level = reputation.risk_level
            
            result = RateLimitResult(
                allowed=allowed,
                remaining_requests=remaining_requests,
                reset_time=reset_time,
                violation_type=violation_type,
                penalty_applied=penalty_applied,
                risk_level=risk_level,
                metadata={
                    "requests_in_window": requests_in_window,
                    "adaptive_limit": adaptive_limit,
                    "burst_detected": burst_detected,
                    "fingerprint": fingerprint
                }
            )
            
            # Log significant events
            if not allowed or burst_detected or penalty_applied:
                self._log_violation(identifier, request_data, result)
            
            return result
    
    def _get_adaptive_limit(self, identifier: str, request_data: Dict[str, Any]) -> float:
        """Get adaptive rate limit based on IP reputation"""
        if not self.config.adaptive_enabled:
            return self.config.requests_per_second
        
        base_limit = self.config.requests_per_second
        
        # Get IP reputation
        ip_address = request_data.get("ip_address", "")
        if not ip_address:
            return base_limit
        
        reputation = self.ip_scoring.get_ip_reputation(ip_address)
        
        # Adjust limit based on risk level
        risk_multipliers = {
            RiskLevel.LOW: 1.0,
            RiskLevel.MEDIUM: 0.8,
            RiskLevel.HIGH: 0.5,
            RiskLevel.CRITICAL: 0.2,
            RiskLevel.BLOCKED: 0.0
        }
        
        multiplier = risk_multipliers.get(reputation.risk_level, 1.0)
        adaptive_limit = base_limit * multiplier
        
        # Store for monitoring
        self.adaptive_limits[identifier] = adaptive_limit
        
        return max(adaptive_limit, 1.0)  # Minimum 1 request per second
    
    def _check_burst(self, identifier: str, current_time: float, request_data: Dict[str, Any]) -> bool:
        """Check for burst activity"""
        burst_window = self.burst_windows[identifier]
        burst_window.append(current_time)
        
        # Remove old requests outside burst window
        cutoff_time = current_time - 5.0  # 5 second burst window
        while burst_window and burst_window[0] < cutoff_time:
            burst_window.popleft()
        
        # Check if burst threshold exceeded
        burst_threshold = self._get_burst_threshold(identifier, request_data)
        return len(burst_window) > burst_threshold
    
    def _get_burst_threshold(self, identifier: str, request_data: Dict[str, Any]) -> int:
        """Get adaptive burst threshold"""
        if not self.config.adaptive_enabled:
            return self.config.burst_size
        
        base_threshold = self.config.burst_size
        
        # Adjust based on IP risk
        ip_address = request_data.get("ip_address", "")
        if ip_address:
            reputation = self.ip_scoring.get_ip_reputation(ip_address)
            
            risk_multipliers = {
                RiskLevel.LOW: 1.0,
                RiskLevel.MEDIUM: 0.8,
                RiskLevel.HIGH: 0.6,
                RiskLevel.CRITICAL: 0.3,
                RiskLevel.BLOCKED: 0.1
            }
            
            multiplier = risk_multipliers.get(reputation.risk_level, 1.0)
            adaptive_threshold = int(base_threshold * multiplier)
            
            self.burst_thresholds[identifier] = adaptive_threshold
            return max(adaptive_threshold, 1)
        
        return base_threshold
    
    def _apply_penalty(self, identifier: str, request_data: Dict[str, Any], violation: ViolationType) -> bool:
        """Apply penalty for violation"""
        if not self.config.progressive_penalties:
            return False
        
        ip_address = request_data.get("ip_address", "")
        if not ip_address:
            return False
        
        # Apply penalty based on violation type
        if violation == ViolationType.BURST_DETECTED:
            penalty_duration = timedelta(minutes=5)
            self.ip_scoring.quarantine_ip(ip_address, penalty_duration)
            return True
        elif violation == ViolationType.RATE_LIMIT:
            penalty_duration = timedelta(minutes=15)
            self.ip_scoring.quarantine_ip(ip_address, penalty_duration)
            return True
        
        return False
    
    def _log_violation(self, identifier: str, request_data: Dict[str, Any], result: RateLimitResult):
        """Log rate limit violation"""
        self.logger.warning(
            "Rate limit violation",
            identifier=identifier,
            ip_address=request_data.get("ip_address"),
            violation_type=result.violation_type.value if result.violation_type else None,
            risk_level=result.risk_level.value,
            requests_in_window=result.metadata.get("requests_in_window", 0),
            adaptive_limit=result.metadata.get("adaptive_limit", 0),
            burst_detected=result.metadata.get("burst_detected", False),
            penalty_applied=result.penalty_applied
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        with self._lock:
            return {
                "enabled": self.enabled,
                "config": {
                    "name": self.config.name,
                    "requests_per_second": self.config.requests_per_second,
                    "burst_size": self.config.burst_size,
                    "window_size": self.config.window_size,
                    "adaptive_enabled": self.config.adaptive_enabled,
                    "ip_scoring_enabled": self.config.ip_scoring_enabled
                },
                "active_identifiers": len(self.request_windows),
                "adaptive_limits": dict(list(self.adaptive_limits.items())[:10]),  # Sample
                "burst_thresholds": dict(list(self.burst_thresholds.items())[:10])  # Sample
            }


class SecurityRateEngine:
    """Main security rate engine manager"""
    
    def __init__(self):
        self.enabled = os.getenv("SECURITY_RATE_ENGINE_ENABLED", "true").lower() == "true"
        
        # Rate limiters
        self.rate_limiters: Dict[str, RateLimiter] = {}
        
        # Components
        self.ip_scoring = ip_scoring_engine
        self.fingerprinting = ClientFingerprint()
        
        # Global statistics
        self.global_stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "quarantined_ips": 0,
            "blocked_ips": 0,
            "violations_by_type": defaultdict(int)
        }
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        self.logger = get_structured_logger("security_rate_engine")
        
        # Initialize default rate limiters
        self._initialize_default_limiters()
        
        self.logger.info("Security rate engine initialized", enabled=self.enabled)
    
    def _initialize_default_limiters(self):
        """Initialize default rate limiters"""
        default_configs = {
            "global": RateLimitConfig(
                name="global",
                requests_per_second=100.0,
                burst_size=200,
                window_size=60
            ),
            "api": RateLimitConfig(
                name="api",
                requests_per_second=50.0,
                burst_size=100,
                window_size=60
            ),
            "auth": RateLimitConfig(
                name="auth",
                requests_per_second=10.0,
                burst_size=20,
                window_size=60
            ),
            "sensitive": RateLimitConfig(
                name="sensitive",
                requests_per_second=5.0,
                burst_size=10,
                window_size=60
            )
        }
        
        for name, config in default_configs.items():
            self.rate_limiters[name] = RateLimiter(config)
    
    async def check_rate_limit(self, limiter_name: str, identifier: str, 
                             request_data: Dict[str, Any]) -> RateLimitResult:
        """Check rate limit using specified limiter"""
        if not self.enabled:
            return RateLimitResult(
                allowed=True,
                remaining_requests=999999,
                reset_time=datetime.utcnow() + timedelta(seconds=60)
            )
        
        with self._lock:
            self.global_stats["total_requests"] += 1
        
        limiter = self.rate_limiters.get(limiter_name)
        if not limiter:
            # Fallback to global limiter
            limiter = self.rate_limiters["global"]
        
        result = await limiter.check_rate_limit(identifier, request_data)
        
        with self._lock:
            if not result.allowed:
                self.global_stats["blocked_requests"] += 1
            
            if result.violation_type:
                self.global_stats["violations_by_type"][result.violation_type.value] += 1
        
        return result
    
    def create_rate_limiter(self, name: str, **kwargs) -> RateLimiter:
        """Create new rate limiter"""
        config = RateLimitConfig(name=name, **kwargs)
        limiter = RateLimiter(config)
        
        with self._lock:
            self.rate_limiters[name] = limiter
        
        self.logger.info("Rate limiter created", name=name, config=kwargs)
        return limiter
    
    def get_rate_limiter(self, name: str) -> Optional[RateLimiter]:
        """Get rate limiter by name"""
        with self._lock:
            return self.rate_limiters.get(name)
    
    def block_ip(self, ip_address: str, duration: timedelta):
        """Block IP address"""
        self.ip_scoring.block_ip(ip_address, duration)
        
        with self._lock:
            self.global_stats["blocked_ips"] += 1
    
    def quarantine_ip(self, ip_address: str, duration: timedelta):
        """Quarantine IP address"""
        self.ip_scoring.quarantine_ip(ip_address, duration)
        
        with self._lock:
            self.global_stats["quarantined_ips"] += 1
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is blocked"""
        return self.ip_scoring.is_ip_blocked(ip_address)
    
    def get_ip_reputation(self, ip_address: str) -> IPReputation:
        """Get IP reputation"""
        return self.ip_scoring.get_ip_reputation(ip_address)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        with self._lock:
            rate_limiter_stats = {}
            for name, limiter in self.rate_limiters.items():
                rate_limiter_stats[name] = limiter.get_statistics()
            
            return {
                "enabled": self.enabled,
                "global_stats": dict(self.global_stats),
                "rate_limiters": rate_limiter_stats,
                "ip_scoring": self.ip_scoring.get_statistics(),
                "client_fingerprinting": {
                    "enabled": self.fingerprinting.enabled
                }
            }


# Global instances
ip_scoring_engine = IPScoringEngine()
security_rate_engine = SecurityRateEngine()


async def check_rate_limit(limiter_name: str, identifier: str, request_data: Dict[str, Any]) -> RateLimitResult:
    """Check rate limit"""
    return await security_rate_engine.check_rate_limit(limiter_name, identifier, request_data)


def block_ip(ip_address: str, duration: timedelta):
    """Block IP address"""
    security_rate_engine.block_ip(ip_address, duration)


def quarantine_ip(ip_address: str, duration: timedelta):
    """Quarantine IP address"""
    security_rate_engine.quarantine_ip(ip_address, duration)


def is_ip_blocked(ip_address: str) -> bool:
    """Check if IP is blocked"""
    return security_rate_engine.is_ip_blocked(ip_address)


def get_rate_engine_statistics() -> Dict[str, Any]:
    """Get rate engine statistics"""
    return security_rate_engine.get_statistics()
