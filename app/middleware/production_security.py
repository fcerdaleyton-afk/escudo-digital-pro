"""
Production Security Middleware for Mary V5
Implements comprehensive security hardening for production deployment
"""

import os
import re
import time
import hashlib
from typing import Dict, List, Optional, Any, Set
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.dependencies import logger


class ProductionSecurityMiddleware(BaseHTTPMiddleware):
    """
    Production security middleware implementing:
    - Cloudflare proxy support
    - WAF rules
    - Advanced security headers
    - Anti-bot protection
    - Application fingerprinting protection
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.enabled = os.getenv("PRODUCTION_SECURITY_ENABLED", "true").lower() == "true"
        
        # Security configuration
        self.cloudflare_ips = self._load_cloudflare_ips()
        self.waf_rules = self._load_waf_rules()
        self.bot_patterns = self._load_bot_patterns()
        self.rate_limits = self._load_rate_limits()
        
        # Security headers configuration
        self.security_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
            "Content-Security-Policy": self._get_csp_header(),
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "cross-origin",
            "Expect-CT": "max-age=86400, enforce",
            "NEL": '{"report_to":"https://nel.example.com","max_age":86400}',
            "Report-To": '{"group":"default","max_age":10886400,"endpoints":[{"url":"https://reports.example.com"}]}'
        }
        
        logger.info("Production security middleware initialized", enabled=self.enabled)
    
    def _load_cloudflare_ips(self) -> Set[str]:
        """Load Cloudflare IP ranges for proxy detection"""
        cf_ips = set()
        
        # Cloudflare IPv4 ranges
        cf_ipv4 = [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
        ]
        
        # Cloudflare IPv6 ranges
        cf_ipv6 = [
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
            "2405:b500::/32", "2405:8100::/32", "2c0f:f248::/32",
            "2a06:98c0::/29", "2c0f:f248::/32"
        ]
        
        cf_ips.update(cf_ipv4)
        cf_ips.update(cf_ipv6)
        
        return cf_ips
    
    def _load_waf_rules(self) -> List[Dict[str, Any]]:
        """Load WAF rules for common attack patterns"""
        return [
            {
                "name": "SQL Injection",
                "pattern": r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
                "action": "block",
                "severity": "high"
            },
            {
                "name": "XSS Attacks",
                "pattern": r"(?i)(<script|javascript:|onload=|onerror=|alert\(|document\.cookie)",
                "action": "block",
                "severity": "high"
            },
            {
                "name": "Command Injection",
                "pattern": r"(?i)(;|\||&|\$\(|`|\$\{|\$\[)",
                "action": "block",
                "severity": "critical"
            },
            {
                "name": "Path Traversal",
                "pattern": r"(?i)(\.\./|\.\.\\|%2e%2f|%2e%5c)",
                "action": "block",
                "severity": "high"
            },
            {
                "name": "LFI/RFI",
                "pattern": r"(?i)(php://|file://|ftp://|http://|https://).*\.(php|asp|jsp|txt)",
                "action": "block",
                "severity": "high"
            }
        ]
    
    def _load_bot_patterns(self) -> List[Dict[str, Any]]:
        """Load bot detection patterns"""
        return [
            {
                "name": "Bad User Agents",
                "patterns": [
                    r"(?i)(bot|crawler|spider|scraper|curl|wget|python|java|perl)",
                    r"(?i)(scrapy|selenium|phantom|headless|automation)",
                    r"(?i)(test|scan|probe|check|audit|security)"
                ],
                "action": "block",
                "severity": "medium"
            },
            {
                "name": "Suspicious Headers",
                "patterns": [
                    r"(?i)(x-forwarded-for|x-real-ip|x-cluster-client-ip)",
                    r"(?i)(via|forwarded|proxy|tunnel)"
                ],
                "action": "log",
                "severity": "low"
            }
        ]
    
    def _load_rate_limits(self) -> Dict[str, int]:
        """Load rate limiting configuration"""
        return {
            "default": 100,  # requests per minute
            "auth": 10,    # auth requests per minute
            "api": 1000,  # API requests per minute
            "upload": 5,    # upload requests per minute
            "admin": 20     # admin requests per minute
        }
    
    def _get_csp_header(self) -> str:
        """Generate Content Security Policy header"""
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: https:",
            "font-src 'self' https://fonts.gstatic.com",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests"
        ]
        
        return "; ".join(csp_directives)
    
    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP is from Cloudflare"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            for cf_range in self.cloudflare_ips:
                if "/" in cf_range:
                    network = ipaddress.ip_network(cf_range)
                    if ip_obj in network:
                        return True
                else:
                    cf_ip = ipaddress.ip_address(cf_range)
                    if ip_obj == cf_ip:
                        return True
            
            return False
        except Exception:
            return False
    
    def _check_waf_rules(self, request: Request) -> Optional[Dict[str, Any]]:
        """Check request against WAF rules"""
        if not self.enabled:
            return None
        
        # Check URL path
        url_path = request.url.path.lower()
        
        # Check query parameters
        query_string = str(request.url.query) if request.url.query else ""
        
        # Check headers
        user_agent = request.headers.get("user-agent", "")
        
        # Combine all data for checking
        check_data = f"{url_path} {query_string} {user_agent}"
        
        for rule in self.waf_rules:
            if re.search(rule["pattern"], check_data):
                logger.warning(
                    "WAF rule triggered",
                    rule=rule["name"],
                    pattern=rule["pattern"],
                    severity=rule["severity"],
                    path=url_path,
                    user_agent=user_agent
                )
                return rule
        
        return None
    
    def _check_bot_patterns(self, request: Request) -> List[Dict[str, Any]]:
        """Check request against bot patterns"""
        if not self.enabled:
            return []
        
        triggered_rules = []
        user_agent = request.headers.get("user-agent", "")
        
        for bot_rule in self.bot_patterns:
            for pattern in bot_rule["patterns"]:
                if re.search(pattern, user_agent):
                    logger.warning(
                        "Bot pattern triggered",
                        rule=bot_rule["name"],
                        pattern=pattern,
                        user_agent=user_agent
                    )
                    triggered_rules.append({
                        "rule": bot_rule["name"],
                        "pattern": pattern,
                        "action": bot_rule["action"]
                    })
        
        return triggered_rules
    
    def _get_client_ip(self, request: Request) -> str:
        """Get real client IP considering Cloudflare"""
        # Check Cloudflare headers first
        cf_headers = [
            "cf-connecting-ip",
            "cf-ray", 
            "cf-visitor",
            "cf-ipcountry"
        ]
        
        # If Cloudflare headers present, use CF-Connecting-IP
        for header in cf_headers:
            if header in request.headers:
                return request.headers[header]
        
        # Fallback to X-Forwarded-For
        if "x-forwarded-for" in request.headers:
            return request.headers["x-forwarded-for"].split(",")[0].strip()
        
        # Final fallback to client.host
        return request.client.host if request.client else "unknown"
    
    def _generate_fingerprint_hash(self, request: Request) -> str:
        """Generate application fingerprint hash for tracking"""
        fingerprint_data = {
            "method": request.method,
            "path": request.url.path,
            "user_agent": request.headers.get("user-agent", ""),
            "accept": request.headers.get("accept", ""),
            "accept_language": request.headers.get("accept-language", ""),
            "accept_encoding": request.headers.get("accept-encoding", "")
        }
        
        fingerprint_str = "|".join(fingerprint_data.values())
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    async def dispatch(self, request: Request, call_next):
        """Main middleware dispatch method"""
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        
        try:
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Check if behind Cloudflare
            is_cf = any(header in request.headers for header in ["cf-connecting-ip", "cf-ray"])
            
            # WAF checking
            waf_violation = self._check_waf_rules(request)
            if waf_violation and waf_violation["action"] == "block":
                logger.error(
                    "WAF block - malicious request",
                    rule=waf_violation["name"],
                    ip=client_ip,
                    path=request.url.path,
                    method=request.method
                )
                return Response(
                    content="Request blocked by Web Application Firewall",
                    status_code=status.HTTP_403_FORBIDDEN,
                    headers=self.security_headers
                )
            
            # Bot checking
            bot_violations = self._check_bot_patterns(request)
            should_block_bot = any(v["action"] == "block" for v in bot_violations)
            
            if should_block_bot:
                logger.error(
                    "Bot block - automated request",
                    ip=client_ip,
                    path=request.url.path,
                    violations=bot_violations
                )
                return Response(
                    content="Automated requests not allowed",
                    status_code=status.HTTP_403_FORBIDDEN,
                    headers=self.security_headers
                )
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            for header, value in self.security_headers.items():
                response.headers[header] = value
            
            # Add custom headers
            response.headers["X-Cloudflare"] = "active" if is_cf else "inactive"
            response.headers["X-WAF-Protected"] = "active"
            response.headers["X-Bot-Protected"] = "active"
            response.headers["X-Fingerprint"] = self._generate_fingerprint_hash(request)
            
            # Remove server headers for fingerprinting protection
            response.headers.pop("server", None)
            response.headers.pop("x-powered-by", None)
            
            # Log request
            duration = (time.time() - start_time) * 1000
            logger.info(
                "Request processed",
                ip=client_ip,
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round(duration, 2),
                cloudflare=is_cf,
                waf_triggered=waf_violation is not None,
                bot_violations=len(bot_violations)
            )
            
            return response
            
        except Exception as e:
            logger.error(
                "Security middleware error",
                error=str(e),
                ip=client_ip if 'client_ip' in locals() else "unknown",
                path=request.url.path
            )
            
            # Return safe error response
            return Response(
                content="Internal security error",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                headers=self.security_headers
            )


class RateLimitTracker:
    """Advanced rate limiting tracker"""
    
    def __init__(self):
        self.requests = {}  # {ip: {endpoint: [timestamps]}}
        self.limits = {
            "default": 100,  # requests per minute
            "auth": 10,    # auth requests per minute
            "api": 1000,  # API requests per minute
            "upload": 5,    # upload requests per minute
            "admin": 20     # admin requests per minute
        }
    
    def is_allowed(self, ip: str, endpoint: str = "default") -> bool:
        """Check if request is allowed based on rate limits"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean old requests
        if ip not in self.requests:
            self.requests[ip] = {}
        
        if endpoint not in self.requests[ip]:
            self.requests[ip][endpoint] = []
        
        # Remove requests older than 1 minute
        self.requests[ip][endpoint] = [
            req_time for req_time in self.requests[ip][endpoint]
            if req_time > minute_ago
        ]
        
        # Check rate limit
        limit = self.limits.get(endpoint, self.limits["default"])
        if len(self.requests[ip][endpoint]) >= limit:
            return False
        
        # Add current request
        self.requests[ip][endpoint].append(current_time)
        return True


# Global rate limit tracker
rate_limit_tracker = RateLimitTracker()


def check_rate_limit(ip: str, endpoint: str = "default") -> bool:
    """Check rate limit for IP and endpoint"""
    return rate_limit_tracker.is_allowed(ip, endpoint)
