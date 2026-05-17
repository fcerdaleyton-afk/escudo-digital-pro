"""
Intelligent Threat Detection System for Mary V5
Detects and responds to various attack patterns including:
- Brute force attacks
- Suspicious request patterns
- Abnormal traffic patterns
- Authentication failures
- Attack fingerprinting
"""

import os
import time
import asyncio
import hashlib
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta

from app.core.dependencies import logger


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    """Types of attacks detected"""
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    AUTH_FAILURE = "auth_failure"
    FLOODING = "flooding"
    SCANNING = "scanning"
    INJECTION_ATTEMPT = "injection_attempt"
    ABNORMAL_PAYLOAD = "abnormal_payload"


@dataclass
class ThreatEvent:
    """Threat event data structure"""
    timestamp: datetime
    attack_type: AttackType
    threat_level: ThreatLevel
    source_ip: str
    user_agent: str
    request_path: str
    request_method: str
    details: Dict[str, Any]
    fingerprint: str
    blocked: bool = False
    duration_minutes: int = 60


@dataclass
class AttackPattern:
    """Attack pattern definition"""
    name: str
    description: str
    detection_rules: List[Dict[str, Any]]
    threat_level: ThreatLevel
    auto_block: bool = True
    block_duration: int = 300  # 5 minutes default


class ThreatIntelligence:
    """Threat intelligence and pattern matching"""
    
    def __init__(self):
        self.attack_patterns = self._load_attack_patterns()
        self.suspicious_user_agents = self._load_suspicious_user_agents()
        self.injection_signatures = self._load_injection_signatures()
    
    def _load_attack_patterns(self) -> List[AttackPattern]:
        """Load known attack patterns"""
        return [
            AttackPattern(
                name="SQL Injection Attempt",
                description="Potential SQL injection in parameters",
                detection_rules=[
                    {"pattern": r"(?i)(union|select|insert|update|delete|drop|exec|script)", "field": "query_params"},
                    {"pattern": r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'", "field": "query_params"},
                    {"pattern": r"(?i)(--|\/\*|\*\/|;)", "field": "query_params"},
                ],
                threat_level=ThreatLevel.HIGH,
                auto_block=True,
                block_duration=600
            ),
            AttackPattern(
                name="XSS Attempt",
                description="Potential Cross-Site Scripting attack",
                detection_rules=[
                    {"pattern": r"(?i)(<script|javascript:|onload=|onerror=)", "field": "query_params"},
                    {"pattern": r"(?i)(<iframe|<object|<embed)", "field": "query_params"},
                ],
                threat_level=ThreatLevel.MEDIUM,
                auto_block=True,
                block_duration=300
            ),
            AttackPattern(
                name="Path Traversal",
                description="Directory traversal attempt",
                detection_rules=[
                    {"pattern": r"(\.\.\/|\.\.\\)", "field": "path"},
                    {"pattern": r"(\/etc\/passwd|\/windows\/system32)", "field": "path"},
                ],
                threat_level=ThreatLevel.HIGH,
                auto_block=True,
                block_duration=600
            ),
            AttackPattern(
                name="Command Injection",
                description="Command injection attempt",
                detection_rules=[
                    {"pattern": r"(?i)(;|\||&|\$\(|\`)", "field": "query_params"},
                    {"pattern": r"(?i)(wget|curl|nc|netcat|bash|sh)", "field": "query_params"},
                ],
                threat_level=ThreatLevel.CRITICAL,
                auto_block=True,
                block_duration=900
            ),
        ]
    
    def _load_suspicious_user_agents(self) -> List[str]:
        """Load suspicious user agent patterns"""
        return [
            r"(?i)(sqlmap|nmap|nikto|dirb|gobuster|burp|owasp|metasploit)",
            r"(?i)(python-requests|wget|powershell|bash)",
            r"(?i)(bot|crawler|spider|scraper)",
        ]
    
    def _load_injection_signatures(self) -> List[str]:
        """Load injection attack signatures"""
        return [
            r"(?i)(union.*select|select.*union)",
            r"(?i)(insert.*into|update.*set|delete.*from)",
            r"(?i)(drop.*table|truncate.*table)",
            r"(?i)(exec.*sp_|xp_cmdshell)",
            r"(?i)(<script.*>.*</script>)",
            r"(?i)(javascript:|vbscript:|onload=|onerror=)",
        ]
    
    def analyze_request(self, request_data: Dict[str, Any]) -> List[ThreatEvent]:
        """Analyze request for potential threats"""
        threats = []
        
        # Check against attack patterns
        for pattern in self.attack_patterns:
            if self._matches_pattern(request_data, pattern):
                threat = ThreatEvent(
                    timestamp=datetime.utcnow(),
                    attack_type=AttackType.INJECTION_ATTEMPT,
                    threat_level=pattern.threat_level,
                    source_ip=request_data.get("source_ip", "unknown"),
                    user_agent=request_data.get("user_agent", ""),
                    request_path=request_data.get("path", ""),
                    request_method=request_data.get("method", ""),
                    details={
                        "pattern_name": pattern.name,
                        "matched_rules": self._get_matched_rules(request_data, pattern),
                        "query_params": request_data.get("query_params", {}),
                    },
                    fingerprint=self._generate_fingerprint(request_data, pattern.name),
                    blocked=pattern.auto_block,
                    duration_minutes=pattern.block_duration
                )
                threats.append(threat)
        
        # Check suspicious user agents
        if self._is_suspicious_user_agent(request_data.get("user_agent", "")):
            threat = ThreatEvent(
                timestamp=datetime.utcnow(),
                attack_type=AttackType.SCANNING,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=request_data.get("source_ip", "unknown"),
                user_agent=request_data.get("user_agent", ""),
                request_path=request_data.get("path", ""),
                request_method=request_data.get("method", ""),
                details={"suspicious_user_agent": True},
                fingerprint=self._generate_fingerprint(request_data, "suspicious_ua"),
                blocked=True,
                duration_minutes=300
            )
            threats.append(threat)
        
        return threats
    
    def _matches_pattern(self, request_data: Dict[str, Any], pattern: AttackPattern) -> bool:
        """Check if request matches attack pattern"""
        for rule in pattern.detection_rules:
            field_value = request_data.get(rule["field"], "")
            if isinstance(field_value, dict):
                # Check all values in dict
                for key, value in field_value.items():
                    if isinstance(value, str) and self._match_pattern(value, rule["pattern"]):
                        return True
            elif isinstance(field_value, str) and self._match_pattern(field_value, rule["pattern"]):
                return True
        return False
    
    def _match_pattern(self, text: str, pattern: str) -> bool:
        """Match text against pattern"""
        import re
        try:
            return bool(re.search(pattern, text))
        except re.error:
            return False
    
    def _get_matched_rules(self, request_data: Dict[str, Any], pattern: AttackPattern) -> List[str]:
        """Get list of matched rules for debugging"""
        matched = []
        for rule in pattern.detection_rules:
            field_value = request_data.get(rule["field"], "")
            if isinstance(field_value, dict):
                for key, value in field_value.items():
                    if isinstance(value, str) and self._match_pattern(value, rule["pattern"]):
                        matched.append(f"{rule['field']}.{key}: {rule['pattern']}")
                        break
            elif isinstance(field_value, str) and self._match_pattern(field_value, rule["pattern"]):
                matched.append(f"{rule['field']}: {rule['pattern']}")
        return matched
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        import re
        # Allow common browsers and legitimate tools
        legitimate_patterns = [
            r"(?i)(mozilla|chrome|safari|edge|firefox|opera)",
            r"(?i)(curl|wget|httpie|postman)",  # Allow for testing
        ]
        
        # First check if it's a legitimate browser/tool
        for pattern in legitimate_patterns:
            if re.search(pattern, user_agent):
                return False
        
        # Then check if it's suspicious
        for pattern in self.suspicious_user_agents:
            if re.search(pattern, user_agent):
                return True
        
        return False
    
    def _generate_fingerprint(self, request_data: Dict[str, Any,], pattern_name: str) -> str:
        """Generate unique fingerprint for attack"""
        fingerprint_data = {
            "source_ip": request_data.get("source_ip", ""),
            "user_agent": request_data.get("user_agent", ""),
            "pattern": pattern_name,
            "timestamp": int(time.time()),
        }
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


class BruteForceDetector:
    """Detects brute force attacks on authentication endpoints"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = {}
        self.max_attempts = int(os.getenv("BRUTE_FORCE_MAX_ATTEMPTS", "5"))
        self.window_minutes = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "15"))
        self.block_duration_minutes = int(os.getenv("BRUTE_FORCE_BLOCK_DURATION", "30"))
    
    def record_failed_attempt(self, source_ip: str, username: str = None) -> Optional[ThreatEvent]:
        """Record failed authentication attempt"""
        current_time = time.time()
        window_start = current_time - (self.window_minutes * 60)
        
        # Initialize IP tracking
        if source_ip not in self.failed_attempts:
            self.failed_attempts[source_ip] = []
        
        # Clean old attempts
        self.failed_attempts[source_ip] = [
            attempt for attempt in self.failed_attempts[source_ip]
            if attempt > window_start
        ]
        
        # Add current attempt
        self.failed_attempts[source_ip].append(current_time)
        
        # Check if threshold exceeded
        if len(self.failed_attempts[source_ip]) >= self.max_attempts:
            threat = ThreatEvent(
                timestamp=datetime.utcnow(),
                attack_type=AttackType.BRUTE_FORCE,
                threat_level=ThreatLevel.HIGH,
                source_ip=source_ip,
                user_agent="",
                request_path="/api/v1/auth/login",
                request_method="POST",
                details={
                    "failed_attempts": len(self.failed_attempts[source_ip]),
                    "window_minutes": self.window_minutes,
                    "target_username": username,
                    "attempts_in_window": self.failed_attempts[source_ip]
                },
                fingerprint=self._generate_brute_force_fingerprint(source_ip, username),
                blocked=True,
                duration_minutes=self.block_duration_minutes
            )
            
            # Block the IP
            self.blocked_ips[source_ip] = current_time + (self.block_duration_minutes * 60)
            
            return threat
        
        return None
    
    def is_ip_blocked(self, source_ip: str) -> bool:
        """Check if IP is currently blocked"""
        if source_ip in self.blocked_ips:
            if time.time() > self.blocked_ips[source_ip]:
                # Block expired
                del self.blocked_ips[source_ip]
                if source_ip in self.failed_attempts:
                    del self.failed_attempts[source_ip]
                return False
            return True
        return False
    
    def get_block_remaining_time(self, source_ip: str) -> int:
        """Get remaining block time in seconds"""
        if source_ip in self.blocked_ips:
            remaining = self.blocked_ips[source_ip] - time.time()
            return max(0, int(remaining))
        return 0
    
    def _generate_brute_force_fingerprint(self, source_ip: str, username: str = None) -> str:
        """Generate fingerprint for brute force attack"""
        fingerprint_data = {
            "source_ip": source_ip,
            "username": username or "unknown",
            "attack_type": "brute_force",
            "timestamp": int(time.time()),
        }
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


class TrafficAnalyzer:
    """Analyzes traffic patterns for anomalies"""
    
    def __init__(self):
        self.request_history = {}
        self.anomaly_threshold = int(os.getenv("TRAFFIC_ANOMALY_THRESHOLD", "100"))  # requests per minute
        self.window_minutes = int(os.getenv("TRAFFIC_ANALYSIS_WINDOW", "5"))
    
    def record_request(self, source_ip: str, path: str, method: str) -> Optional[ThreatEvent]:
        """Record request and check for anomalies"""
        current_time = time.time()
        window_start = current_time - (self.window_minutes * 60)
        
        # Initialize IP tracking
        if source_ip not in self.request_history:
            self.request_history[source_ip] = []
        
        # Clean old requests
        self.request_history[source_ip] = [
            req for req in self.request_history[source_ip]
            if req > window_start
        ]
        
        # Add current request
        self.request_history[source_ip].append(current_time)
        
        # Check for flooding
        if len(self.request_history[source_ip]) > self.anomaly_threshold:
            threat = ThreatEvent(
                timestamp=datetime.utcnow(),
                attack_type=AttackType.FLOODING,
                threat_level=ThreatLevel.MEDIUM,
                source_ip=source_ip,
                user_agent="",
                request_path=path,
                request_method=method,
                details={
                    "requests_per_window": len(self.request_history[source_ip]),
                    "window_minutes": self.window_minutes,
                    "threshold": self.anomaly_threshold
                },
                fingerprint=self._generate_traffic_fingerprint(source_ip, "flooding"),
                blocked=True,
                duration_minutes=15
            )
            return threat
        
        # Check for scanning behavior
        if self._detect_scanning_behavior(source_ip):
            threat = ThreatEvent(
                timestamp=datetime.utcnow(),
                attack_type=AttackType.SCANNING,
                threat_level=ThreatLevel.LOW,
                source_ip=source_ip,
                user_agent="",
                request_path=path,
                request_method=method,
                details={
                    "scanning_detected": True,
                    "unique_paths": len(set(req.get("path", "") for req in self.request_history.get(source_ip, [])))
                },
                fingerprint=self._generate_traffic_fingerprint(source_ip, "scanning"),
                blocked=False,
                duration_minutes=0
            )
            return threat
        
        return None
    
    def _detect_scanning_behavior(self, source_ip: str) -> bool:
        """Detect if IP is scanning multiple endpoints"""
        # This is a simplified implementation
        # In production, you'd track unique paths and methods
        return len(self.request_history.get(source_ip, [])) > 20
    
    def _generate_traffic_fingerprint(self, source_ip: str, attack_type: str) -> str:
        """Generate fingerprint for traffic-based attack"""
        fingerprint_data = {
            "source_ip": source_ip,
            "attack_type": attack_type,
            "timestamp": int(time.time()),
        }
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


# Global instances
threat_intelligence = ThreatIntelligence()
brute_force_detector = BruteForceDetector()
traffic_analyzer = TrafficAnalyzer()
