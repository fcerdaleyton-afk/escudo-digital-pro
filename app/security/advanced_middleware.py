"""
Advanced Security Middleware for Mary V5 Enterprise
Enterprise-grade defensive cybersecurity middleware with banking-grade protection
"""

import os
import re
import time
import json
import hashlib
import ipaddress
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from fastapi import Request, HTTPException, status, Response
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict, deque
import geoip2.database
import redis.asyncio as redis

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class IPReputationFilter:
    """IP reputation and geolocation filtering"""
    
    def __init__(self):
        self.enabled = os.getenv("IP_REPUTATION_ENABLED", "true").lower() == "true"
        self.geoip_db_path = os.getenv("GEOIP_DB_PATH", "/app/data/GeoLite2-Country.mmdb")
        self.blocked_countries = set(os.getenv("BLOCKED_COUNTRIES", "").split(","))
        self.trusted_proxies = set(os.getenv("TRUSTED_PROXIES", "").split(","))
        self.blocked_ips = set()
        self.suspicious_ips = set()
        
        # Load reputation data
        self._load_reputation_data()
        
        logger.info("IP reputation filter initialized", enabled=self.enabled)
    
    def _load_reputation_data(self):
        """Load IP reputation data"""
        try:
            # Load known malicious IPs
            malicious_ips = os.getenv("MALICIOUS_IPS", "")
            if malicious_ips:
                self.blocked_ips.update(ip.strip() for ip in malicious_ips.split(","))
            
            # Load suspicious IP ranges
            suspicious_ranges = os.getenv("SUSPICIOUS_IP_RANGES", "")
            if suspicious_ranges:
                self.suspicious_ips.update(ip.strip() for ip in suspicious_ranges.split(","))
                
        except Exception as e:
            logger.error("Failed to load IP reputation data", error=str(e))
    
    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation score and details"""
        reputation = {
            "ip": ip,
            "score": 0,  # 0-100, higher is more suspicious
            "country": None,
            "is_proxy": False,
            "is_tor": False,
            "is_blocked": ip in self.blocked_ips,
            "is_suspicious": ip in self.suspicious_ips
        }
        
        # Check if blocked
        if reputation["is_blocked"]:
            reputation["score"] = 100
            return reputation
        
        # Geolocation check
        try:
            if os.path.exists(self.geoip_db_path):
                with geoip2.database.Reader(self.geoip_db_path) as reader:
                    response = reader.country(ip)
                    reputation["country"] = response.country.iso_code
                    
                    if reputation["country"] in self.blocked_countries:
                        reputation["score"] += 50
        except Exception:
            pass
        
        # Check for suspicious patterns
        if self._is_suspicious_ip(ip):
            reputation["score"] += 30
            reputation["is_suspicious"] = True
        
        return reputation
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP has suspicious characteristics"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private IPs in public context
            if ip_obj.is_private and not self._is_trusted_proxy(ip):
                return True
            
            # Check for known proxy ranges
            if ip_obj.is_reserved:
                return True
                
        except Exception:
            return True
        
        return False
    
    def _is_trusted_proxy(self, ip: str) -> bool:
        """Check if IP is a trusted proxy"""
        return ip in self.trusted_proxies


class RequestFingerprinter:
    """Advanced request fingerprinting for replay attack detection"""
    
    def __init__(self):
        self.enabled = os.getenv("REQUEST_FINGERPRINTING_ENABLED", "true").lower() == "true"
        self.fingerprint_cache = {}
        self.cache_ttl = int(os.getenv("FINGERPRINT_CACHE_TTL", "3600"))  # 1 hour
        
        logger.info("Request fingerprinter initialized", enabled=self.enabled)
    
    def generate_fingerprint(self, request: Request) -> bytes:
        """Generate unique request fingerprint"""
        fingerprint_data = []
        
        # HTTP method and path
        fingerprint_data.append(request.method)
        fingerprint_data.append(request.url.path)
        
        # Key headers (normalized)
        key_headers = [
            "user-agent", "accept", "accept-language", 
            "accept-encoding", "referer"
        ]
        
        for header in key_headers:
            value = request.headers.get(header, "").lower().strip()
            fingerprint_data.append(value)
        
        # Request body hash (if present)
        if hasattr(request, '_body') and request._body:
            body = request._body
            if isinstance(body, str):
                body = body.encode('utf-8')
            elif not isinstance(body, (bytes, bytearray)):
                body = str(body).encode('utf-8')

            body_hash = hashlib.sha256(body).digest()
            fingerprint_data.append(body_hash.hex())
        
        # Create fingerprint
        fingerprint_str = "|".join(fingerprint_data)
        fingerprint = hashlib.sha256(fingerprint_str.encode()).digest()
        
        return fingerprint
    
    def check_replay_attack(self, fingerprint: str, ip: str) -> bool:
        """Check for replay attacks using fingerprint cache"""
        if not self.enabled:
            return False
        
        current_time = time.time()
        cache_key = f"{ip}:{fingerprint}"
        
        # Normalize fingerprint for string storage
        if isinstance(fingerprint, (bytes, bytearray)):
            cache_key = f"{ip}:{fingerprint.hex()}"

        # Check cache
        if cache_key in self.fingerprint_cache:
            last_seen = self.fingerprint_cache[cache_key]
            if current_time - last_seen < self.cache_ttl:
                return True
        
        # Update cache
        self.fingerprint_cache[cache_key] = current_time
        
        # Clean old entries
        self._cleanup_cache(current_time)
        
        return False
    
    def _cleanup_cache(self, current_time: float):
        """Clean up old fingerprint cache entries"""
        expired_keys = []
        
        for key, timestamp in self.fingerprint_cache.items():
            if current_time - timestamp > self.cache_ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.fingerprint_cache[key]


class ThreatScoringEngine:
    """Advanced threat scoring and anomaly detection"""
    
    def __init__(self):
        self.enabled = os.getenv("THREAT_SCORING_ENABLED", "true").lower() == "true"
        
        # Scoring weights
        self.weights = {
            "suspicious_ip": 30,
            "blocked_country": 25,
            "replay_attack": 40,
            "rate_limit_exceeded": 20,
            "suspicious_headers": 15,
            "malicious_payload": 50,
            "bot_detected": 35,
            "geo_anomaly": 20
        }
        
        # Thresholds
        self.block_threshold = int(os.getenv("THREAT_BLOCK_THRESHOLD", "80"))
        self.alert_threshold = int(os.getenv("THREAT_ALERT_THRESHOLD", "50"))
        
        # Request history for anomaly detection
        self.request_history = defaultdict(lambda: deque(maxlen=100))
        
        logger.info("Threat scoring engine initialized", enabled=self.enabled)
    
    def calculate_threat_score(self, request: Request, ip_info: Dict, 
                             fingerprint_check: bool, rate_limit_status: Dict) -> Dict[str, Any]:
        """Calculate comprehensive threat score"""
        if not self.enabled:
            return {"score": 0, "risk_level": "low", "factors": []}
        
        score = 0
        factors = []
        
        # IP reputation factors
        if ip_info.get("is_blocked"):
            score += self.weights["suspicious_ip"]
            factors.append("blocked_ip")
        
        if ip_info.get("is_suspicious"):
            score += self.weights["suspicious_ip"]
            factors.append("suspicious_ip")
        
        if ip_info.get("country") in ip_info.get("blocked_countries", []):
            score += self.weights["blocked_country"]
            factors.append("blocked_country")
        
        # Replay attack detection
        if fingerprint_check:
            score += self.weights["replay_attack"]
            factors.append("replay_attack")
        
        # Rate limiting
        if rate_limit_status.get("exceeded"):
            score += self.weights["rate_limit_exceeded"]
            factors.append("rate_limit_exceeded")
        
        # Suspicious headers analysis
        suspicious_headers = self._analyze_headers(request)
        if suspicious_headers:
            score += self.weights["suspicious_headers"]
            factors.append("suspicious_headers")
        
        # Malicious payload detection
        if self._detect_malicious_payload(request):
            score += self.weights["malicious_payload"]
            factors.append("malicious_payload")
        
        # Bot detection
        if self._detect_bot(request):
            score += self.weights["bot_detected"]
            factors.append("bot_detected")
        
        # Geographical anomaly detection
        if self._detect_geo_anomaly(ip_info):
            score += self.weights["geo_anomaly"]
            factors.append("geo_anomaly")
        
        # Determine risk level
        if score >= self.block_threshold:
            risk_level = "critical"
        elif score >= self.alert_threshold:
            risk_level = "high"
        elif score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "score": score,
            "risk_level": risk_level,
            "factors": factors,
            "thresholds": {
                "block": self.block_threshold,
                "alert": self.alert_threshold
            }
        }
    
    def _analyze_headers(self, request: Request) -> List[str]:
        """Analyze request headers for suspicious patterns"""
        suspicious = []
        
        # Check for suspicious header combinations
        headers = dict(request.headers)
        
        # Missing common headers
        if not headers.get("user-agent"):
            suspicious.append("missing_user_agent")
        
        # Suspicious user agents
        ua = headers.get("user-agent", "").lower()
        suspicious_patterns = [
            "bot", "crawler", "spider", "scraper", "curl", "wget",
            "python", "java", "perl", "ruby", "php"
        ]
        
        if any(pattern in ua for pattern in suspicious_patterns):
            suspicious.append("automated_user_agent")
        
        # Suspicious header values
        for header, value in headers.items():
            if any(char in value for char in ["<script", "javascript:", "eval("]):
                suspicious.append(f"suspicious_{header}")
        
        return suspicious
    
    def _detect_malicious_payload(self, request: Request) -> bool:
        """Detect malicious payloads in request"""
        # Check URL and query parameters
        url = request.url.path.lower()
        query = str(request.url.query).lower()
        
        # Common attack patterns
        attack_patterns = [
            r"<script[^>]*>", r"javascript:", r"eval\(",
            r"union.*select", r"drop.*table", r"insert.*into",
            r"exec\(", r"system\(", r"shell_exec\(",
            r"\.\./", r"\.\.\\", r"%2e%2f"
        ]
        
        content_to_check = f"{url} {query}"
        
        for pattern in attack_patterns:
            if re.search(pattern, content_to_check, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_bot(self, request: Request) -> bool:
        """Detect automated/bot requests"""
        headers = dict(request.headers)
        ua = headers.get("user-agent", "").lower()
        
        # Bot indicators
        bot_indicators = [
            "bot", "crawler", "spider", "scraper", "curl", "wget",
            "python-requests", "java", "perl", "ruby", "php"
        ]
        
        return any(indicator in ua for indicator in bot_indicators)
    
    def _detect_geo_anomaly(self, ip_info: Dict) -> bool:
        """Detect geographical anomalies"""
        # Simple anomaly detection based on country
        # In production, this would use more sophisticated analysis
        country = ip_info.get("country")
        
        # List of countries that might be anomalous for this application
        anomaly_countries = set(os.getenv("ANOMALY_COUNTRIES", "").split(","))
        
        return country in anomaly_countries if country else False


class AdvancedRateLimiter:
    """Advanced rate limiting with multiple strategies"""
    
    def __init__(self):
        self.enabled = os.getenv("ADVANCED_RATE_LIMITING_ENABLED", "true").lower() == "true"
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        self.redis_client = None
        
        # Rate limiting strategies
        self.strategies = {
            "global": {"requests": 10000, "window": 60},  # Global limit
            "ip": {"requests": 100, "window": 60},        # Per IP limit
            "endpoint": {"requests": 1000, "window": 60}, # Per endpoint limit
            "user": {"requests": 500, "window": 60}       # Per user limit
        }
        
        # Load custom strategies from environment
        self._load_custom_strategies()
        
        logger.info("Advanced rate limiter initialized", enabled=self.enabled)
    
    async def initialize(self):
        """Initialize Redis connection"""
        if self.enabled and not self.redis_client:
            try:
                self.redis_client = await redis.from_url(self.redis_url)
                logger.info("Redis connection established for rate limiting")
            except Exception as e:
                logger.error("Failed to connect to Redis for rate limiting", error=str(e))
    
    def _load_custom_strategies(self):
        """Load custom rate limiting strategies from environment"""
        custom_strategies = os.getenv("CUSTOM_RATE_LIMITS", "")
        if custom_strategies:
            try:
                for strategy in custom_strategies.split(";"):
                    if ":" in strategy:
                        name, config = strategy.split(":", 1)
                        if "," in config:
                            requests, window = config.split(",", 1)
                            self.strategies[name.strip()] = {
                                "requests": int(requests),
                                "window": int(window)
                            }
            except Exception as e:
                logger.error("Failed to load custom rate limits", error=str(e))
    
    async def check_rate_limit(self, key: str, strategy: str = "ip") -> Dict[str, Any]:
        """Check rate limit for a given key"""
        if not self.enabled or not self.redis_client:
            return {"allowed": True, "remaining": float('inf'), "reset_time": 0}
        
        if strategy not in self.strategies:
            strategy = "ip"
        
        config = self.strategies[strategy]
        redis_key = f"rate_limit:{strategy}:{key}"
        
        try:
            # Use Redis sliding window algorithm
            current_time = int(time.time())
            window_start = current_time - config["window"]
            
            # Remove old entries
            await self.redis_client.zremrangebyscore(redis_key, 0, window_start)
            
            # Count current requests
            current_requests = await self.redis_client.zcard(redis_key)
            
            # Check if limit exceeded
            if current_requests >= config["requests"]:
                # Get oldest request time for reset time
                oldest = await self.redis_client.zrange(redis_key, 0, 0, withscores=True)
                reset_time = int(oldest[0][1]) + config["window"] if oldest else current_time + config["window"]
                
                return {
                    "allowed": False,
                    "remaining": 0,
                    "reset_time": reset_time,
                    "current": current_requests,
                    "limit": config["requests"]
                }
            
            # Add current request
            await self.redis_client.zadd(redis_key, {str(current_time): current_time})
            await self.redis_client.expire(redis_key, config["window"])
            
            return {
                "allowed": True,
                "remaining": config["requests"] - current_requests - 1,
                "reset_time": current_time + config["window"],
                "current": current_requests + 1,
                "limit": config["requests"]
            }
            
        except Exception as e:
            logger.error("Rate limiting check failed", error=str(e))
            return {"allowed": True, "remaining": float('inf'), "reset_time": 0}


class AdvancedSecurityMiddleware(BaseHTTPMiddleware):
    """
    Enterprise-grade security middleware with comprehensive protection
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.enabled = os.getenv("ADVANCED_SECURITY_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.ip_filter = IPReputationFilter()
        self.fingerprinter = RequestFingerprinter()
        self.threat_scorer = ThreatScoringEngine()
        self.rate_limiter = AdvancedRateLimiter()
        
        # Security configuration
        self.block_on_critical = os.getenv("BLOCK_ON_CRITICAL", "true").lower() == "true"
        self.log_all_requests = os.getenv("LOG_ALL_REQUESTS", "false").lower() == "true"
        
        logger.info("Advanced security middleware initialized", enabled=self.enabled)
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch method"""
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        
        try:
            # Get client IP (considering proxies)
            client_ip = self._get_client_ip(request)
            
            # IP reputation check
            ip_info = self.ip_filter.get_ip_reputation(client_ip)
            
            # Block immediately if IP is blocked
            if ip_info.get("is_blocked"):
                await self._log_security_event("blocked_ip", request, ip_info)
                return self._create_block_response("IP blocked", ip_info)
            
            # Generate request fingerprint
            fingerprint = self.fingerprinter.generate_fingerprint(request)
            
            # Check for replay attacks
            replay_attack = self.fingerprinter.check_replay_attack(fingerprint, client_ip)
            
            # Rate limiting
            rate_limit_key = f"{client_ip}:{request.url.path}"
            rate_limit_status = await self.rate_limiter.check_rate_limit(rate_limit_key)
            
            # Calculate threat score
            threat_score = self.threat_scorer.calculate_threat_score(
                request, ip_info, replay_attack, rate_limit_status
            )
            
            # Log security event if high risk
            if threat_score["risk_level"] in ["high", "critical"]:
                await self._log_security_event("high_risk_request", request, {
                    "threat_score": threat_score,
                    "ip_info": ip_info,
                    "fingerprint": fingerprint
                })
            
            # Block if critical threat
            if threat_score["risk_level"] == "critical" and self.block_on_critical:
                return self._create_block_response("Threat detected", threat_score)
            
            # Block if rate limited
            if not rate_limit_status.get("allowed", True):
                await self._log_security_event("rate_limit_exceeded", request, rate_limit_status)
                return self._create_block_response("Rate limit exceeded", rate_limit_status)
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response, threat_score)
            
            # Log request if enabled
            if self.log_all_requests or threat_score["score"] > 0:
                await self._log_request(request, response, threat_score, start_time)
            
            return response
            
        except Exception as e:
            logger.error("Security middleware error", error=str(e))
            return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Get real client IP considering proxies"""
        # Check for proxy headers
        proxy_headers = [
            "x-forwarded-for", "x-real-ip", "cf-connecting-ip",
            "x-cluster-client-ip", "x-forwarded"
        ]
        
        for header in proxy_headers:
            if header in request.headers:
                ip = request.headers[header].split(",")[0].strip()
                if ip and ip != "unknown":
                    return ip
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"
    
    def _add_security_headers(self, response: Response, threat_score: Dict):
        """Add security headers to response"""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Threat-Score": str(threat_score["score"]),
            "X-Risk-Level": threat_score["risk_level"]
        }
        
        for header, value in headers.items():
            response.headers[header] = value
    
    def _create_block_response(self, reason: str, details: Dict) -> Response:
        """Create security block response"""
        return Response(
            content=f"Request blocked: {reason}",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={
                "X-Block-Reason": reason,
                "Content-Type": "text/plain"
            }
        )
    
    async def _log_security_event(self, event_type: str, request: Request, details: Dict):
        """Log security event"""
        fingerprint = details.get("fingerprint")
        if isinstance(fingerprint, (bytes, bytearray)):
            details = {**details, "fingerprint": fingerprint.hex()}

        log_security_event(
            event_type,
            {
                "ip": self._get_client_ip(request),
                "method": request.method,
                "path": request.url.path,
                "user_agent": request.headers.get("user-agent", ""),
                **details
            }
        )
    
    async def _log_request(self, request: Request, response: Response, 
                          threat_score: Dict, start_time: float):
        """Log request with security context"""
        duration = (time.time() - start_time) * 1000
        
        log_audit_event(
            "request_processed",
            resource=f"{request.method} {request.url.path}",
            result="success" if response.status_code < 400 else "error",
            details={
                "duration_ms": round(duration, 2),
                "threat_score": threat_score["score"],
                "risk_level": threat_score["risk_level"],
                "status_code": response.status_code
            }
        )


# Global middleware instance
advanced_security_middleware = None


def get_advanced_security_middleware(app):
    """Get or create advanced security middleware instance"""
    global advanced_security_middleware
    if advanced_security_middleware is None:
        advanced_security_middleware = AdvancedSecurityMiddleware(app)
    return advanced_security_middleware
