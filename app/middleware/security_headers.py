"""
MARY V5 SHIELD CORE - Security Headers Middleware
Comprehensive security headers implementation for enterprise protection
"""

import os
import time
from typing import Dict, List, Optional, Any
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from urllib.parse import urlparse

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Advanced security headers middleware for enterprise-grade protection
    Implements comprehensive security headers following OWASP best practices
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.enabled = os.getenv("SECURITY_HEADERS_ENABLED", "true").lower() == "true"
        
        # Security header configuration
        self.hsts_enabled = os.getenv("HSTS_ENABLED", "true").lower() == "true"
        self.hsts_max_age = os.getenv("HSTS_MAX_AGE", "31536000")  # 1 year
        self.hsts_include_subdomains = os.getenv("HSTS_INCLUDE_SUBDOMAINS", "true").lower() == "true"
        self.hsts_preload = os.getenv("HSTS_PRELOAD", "true").lower() == "true"
        
        # CSP configuration
        self.csp_enabled = os.getenv("CSP_ENABLED", "true").lower() == "true"
        self.csp_report_only = os.getenv("CSP_REPORT_ONLY", "false").lower() == "true"
        self.csp_report_uri = os.getenv("CSP_REPORT_URI", "/api/v1/security/csp-report")
        
        # Frame protection
        self.frame_options = os.getenv("X_FRAME_OPTIONS", "DENY")
        
        # Content type protection
        self.content_type_options = os.getenv("X_CONTENT_TYPE_OPTIONS", "nosniff")
        
        # Referrer policy
        self.referrer_policy = os.getenv("REFERRER_POLICY", "strict-origin-when-cross-origin")
        
        # Permissions policy
        self.permissions_policy = os.getenv("PERMISSIONS_POLICY", self._default_permissions_policy())
        
        # Additional security headers
        self.cross_origin_embedder_policy = os.getenv("CROSS_ORIGIN_EMBEDDER_POLICY", "require-corp")
        self.cross_origin_opener_policy = os.getenv("CROSS_ORIGIN_OPENER_POLICY", "same-origin")
        self.cross_origin_resource_policy = os.getenv("CROSS_ORIGIN_RESOURCE_POLICY", "same-origin")
        
        # Custom headers
        self.custom_headers = self._load_custom_headers()
        
        # Header statistics
        self.header_stats = {
            "requests_processed": 0,
            "headers_added": defaultdict(int),
            "violations": defaultdict(int)
        }
        
        logger.info("Security headers middleware initialized", enabled=self.enabled)
    
    def _default_permissions_policy(self) -> str:
        """Default permissions policy following least privilege principle"""
        policies = [
            "geolocation=()",
            "microphone=()",
            "camera=()",
            "payment=()",
            "usb=()",
            "magnetometer=()",
            "gyroscope=()",
            "accelerometer=()",
            "ambient-light-sensor=()",
            "autoplay=()",
            "document-domain=()",
            "encrypted-media=()",
            "fullscreen=()",
            "picture-in-picture=()",
            "publickey-credentials-get=()",
            "sync-xhr=()",
            "xr=()",
            "interest-cohort=()"
        ]
        return ", ".join(policies)
    
    def _load_custom_headers(self) -> Dict[str, str]:
        """Load custom security headers from environment"""
        custom_headers = {}
        
        # Load custom headers from environment variables
        custom_header_vars = {
            "X_CUSTOM_SECURITY": os.getenv("X_CUSTOM_SECURITY"),
            "X_PROTECTION_LEVEL": os.getenv("X_PROTECTION_LEVEL", "enterprise"),
            "X_SECURITY_POLICY": os.getenv("X_SECURITY_POLICY", "strict"),
            "X_CONTENT_SECURITY": os.getenv("X_CONTENT_SECURITY", "high"),
            "X_FRAME_OPTIONS_LEGACY": os.getenv("X_FRAME_OPTIONS_LEGACY"),
            "X_XSS_PROTECTION": os.getenv("X_XSS_PROTECTION", "1; mode=block"),
            "X_PERMITTED_CROSS_DOMAIN_POLICIES": os.getenv("X_PERMITTED_CROSS_DOMAIN_POLICIES", "none"),
            "X_WEBKIT_CSP": os.getenv("X_WEBKIT_CSP"),
            "X_CONTENT_SECURITY_POLICY": os.getenv("X_CONTENT_SECURITY_POLICY")
        }
        
        for key, value in custom_header_vars.items():
            if value:
                custom_headers[key] = value
        
        return custom_headers
    
    async def dispatch(self, request: Request, call_next):
        """Process request and add security headers"""
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        
        try:
            # Process request
            response = await call_next(request)
            
            # Add security headers
            await self._add_security_headers(request, response)
            
            # Update statistics
            self.header_stats["requests_processed"] += 1
            
            # Log header application
            duration = (time.time() - start_time) * 1000
            await self._log_header_application(request, response, duration)
            
            return response
            
        except Exception as e:
            logger.error("Security headers middleware error", error=str(e))
            return await call_next(request)
    
    async def _add_security_headers(self, request: Request, response: Response):
        """Add comprehensive security headers to response"""
        headers_added = []
        
        # HTTP Strict Transport Security (HSTS)
        if self.hsts_enabled and request.url.scheme == "https":
            hsts_value = f"max-age={self.hsts_max_age}"
            
            if self.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            
            if self.hsts_preload:
                hsts_value += "; preload"
            
            response.headers["Strict-Transport-Security"] = hsts_value
            headers_added.append("Strict-Transport-Security")
        
        # Content Security Policy (CSP)
        if self.csp_enabled:
            csp_value = self._generate_csp_header(request)
            csp_header = "Content-Security-Policy-Report-Only" if self.csp_report_only else "Content-Security-Policy"
            response.headers[csp_header] = csp_value
            headers_added.append(csp_header)
        
        # X-Frame-Options
        if self.frame_options:
            response.headers["X-Frame-Options"] = self.frame_options
            headers_added.append("X-Frame-Options")
        
        # X-Content-Type-Options
        if self.content_type_options:
            response.headers["X-Content-Type-Options"] = self.content_type_options
            headers_added.append("X-Content-Type-Options")
        
        # Referrer Policy
        if self.referrer_policy:
            response.headers["Referrer-Policy"] = self.referrer_policy
            headers_added.append("Referrer-Policy")
        
        # Permissions Policy
        if self.permissions_policy:
            response.headers["Permissions-Policy"] = self.permissions_policy
            headers_added.append("Permissions-Policy")
        
        # Cross-Origin Policies
        if self.cross_origin_embedder_policy:
            response.headers["Cross-Origin-Embedder-Policy"] = self.cross_origin_embedder_policy
            headers_added.append("Cross-Origin-Embedder-Policy")
        
        if self.cross_origin_opener_policy:
            response.headers["Cross-Origin-Opener-Policy"] = self.cross_origin_opener_policy
            headers_added.append("Cross-Origin-Opener-Policy")
        
        if self.cross_origin_resource_policy:
            response.headers["Cross-Origin-Resource-Policy"] = self.cross_origin_resource_policy
            headers_added.append("Cross-Origin-Resource-Policy")
        
        # Custom security headers
        for header_name, header_value in self.custom_headers.items():
            response.headers[header_name] = header_value
            headers_added.append(header_name)
        
        # Update statistics
        for header in headers_added:
            self.header_stats["headers_added"][header] += 1
        
        # Add security context header
        response.headers["X-Security-Context"] = json.dumps({
            "headers_applied": headers_added,
            "protection_level": "enterprise",
            "timestamp": time.time()
        })
    
    def _generate_csp_header(self, request: Request) -> str:
        """Generate Content Security Policy header"""
        # Base CSP directives
        directives = {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src": "'self' 'unsafe-inline'",
            "img-src": "'self' data: https:",
            "font-src": "'self'",
            "connect-src": "'self'",
            "frame-src": "'none'",
            "object-src": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "frame-ancestors": "'none'",
            "upgrade-insecure-requests": ""
        }
        
        # Allow specific domains for API endpoints
        allowed_domains = os.getenv("CSP_ALLOWED_DOMAINS", "")
        if allowed_domains:
            domains = allowed_domains.split(",")
            directives["connect-src"] += " " + " ".join(domains)
            directives["script-src"] += " " + " ".join(domains)
        
        # Add report URI if CSP is in report-only mode
        if self.csp_report_only and self.csp_report_uri:
            directives["report-uri"] = self.csp_report_uri
            directives["report-to"] = "csp-endpoint"
        
        # Build CSP header
        csp_parts = []
        for directive, value in directives.items():
            if value:
                csp_parts.append(f"{directive} {value}")
            else:
                csp_parts.append(directive)
        
        return "; ".join(csp_parts)
    
    async def _log_header_application(self, request: Request, response: Response, duration: float):
        """Log security header application"""
        headers_applied = [
            header for header in response.headers.keys()
            if any(keyword in header.lower() for keyword in [
                "strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options", "referrer-policy",
                "permissions-policy", "cross-origin"
            ])
        ]
        
        log_audit_event(
            "security_headers_applied",
            user=getattr(request.state, "user_id", None),
            resource=f"{request.method} {request.url.path}",
            result="success",
            details={
                "headers_applied": headers_applied,
                "duration_ms": round(duration, 2),
                "response_status": response.status_code,
                "client_ip": self._get_client_ip(request)
            }
        )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check for proxy headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def get_header_statistics(self) -> Dict[str, Any]:
        """Get security header statistics"""
        return {
            "enabled": self.enabled,
            "requests_processed": self.header_stats["requests_processed"],
            "headers_applied": dict(self.header_stats["headers_added"]),
            "violations": dict(self.header_stats["violations"]),
            "configuration": {
                "hsts_enabled": self.hsts_enabled,
                "csp_enabled": self.csp_enabled,
                "frame_options": self.frame_options,
                "referrer_policy": self.referrer_policy
            }
        }
    
    async def handle_csp_violation(self, request: Request, violation_data: Dict[str, Any]):
        """Handle Content Security Policy violations"""
        try:
            # Extract violation details
            blocked_uri = violation_data.get("blocked-uri", "")
            violated_directive = violation_data.get("violated-directive", "")
            document_uri = violation_data.get("document-uri", "")
            
            # Log violation
            log_security_event(
                "csp_violation",
                {
                    "blocked_uri": blocked_uri,
                    "violated_directive": violated_directive,
                    "document_uri": document_uri,
                    "client_ip": self._get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "user_id": getattr(request.state, "user_id", None)
                }
            )
            
            # Update statistics
            self.header_stats["violations"]["csp_violations"] += 1
            
            # Check if violation indicates an attack
            if self._is_suspicious_csp_violation(violation_data):
                await self._handle_suspicious_violation(request, violation_data)
        
        except Exception as e:
            logger.error("CSP violation handling error", error=str(e))
    
    def _is_suspicious_csp_violation(self, violation_data: Dict[str, Any]) -> bool:
        """Check if CSP violation is suspicious"""
        blocked_uri = violation_data.get("blocked-uri", "").lower()
        
        # Suspicious patterns
        suspicious_patterns = [
            "javascript:", "data:", "vbscript:", "file:",
            "http://evil", "malware", "exploit", "xss",
            "injection", "script", "payload"
        ]
        
        return any(pattern in blocked_uri for pattern in suspicious_patterns)
    
    async def _handle_suspicious_violation(self, request: Request, violation_data: Dict[str, Any]):
        """Handle suspicious CSP violations"""
        # Create security event
        from app.security.security_engine import process_security_event
        
        event_data = {
            "event_type": "csp_violation",
            "threat_level": "medium",
            "source_ip": self._get_client_ip(request),
            "user_id": getattr(request.state, "user_id", None),
            "description": "Suspicious Content Security Policy violation detected",
            "details": {
                "violation_data": violation_data,
                "user_agent": request.headers.get("user-agent", ""),
                "request_path": request.url.path,
                "method": request.method
            }
        }
        
        await process_security_event(event_data)


class SecurityHeadersValidator:
    """Validator for security headers compliance"""
    
    def __init__(self):
        self.required_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        self.recommended_headers = [
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy"
        ]
    
    def validate_headers(self, response_headers: Dict[str, str]) -> Dict[str, Any]:
        """Validate security headers compliance"""
        validation_result = {
            "compliant": True,
            "missing_required": [],
            "missing_recommended": [],
            "issues": [],
            "score": 0
        }
        
        # Check required headers
        for header in self.required_headers:
            if header not in response_headers:
                validation_result["missing_required"].append(header)
                validation_result["compliant"] = False
        
        # Check recommended headers
        for header in self.recommended_headers:
            if header not in response_headers:
                validation_result["missing_recommended"].append(header)
        
        # Validate specific header values
        issues = self._validate_header_values(response_headers)
        validation_result["issues"] = issues
        
        # Calculate compliance score
        total_headers = len(self.required_headers) + len(self.recommended_headers)
        present_headers = total_headers - len(validation_result["missing_required"]) - len(validation_result["missing_recommended"])
        validation_result["score"] = (present_headers / total_headers) * 100
        
        return validation_result
    
    def _validate_header_values(self, headers: Dict[str, str]) -> List[str]:
        """Validate specific header values"""
        issues = []
        
        # Validate HSTS
        if "Strict-Transport-Security" in headers:
            hsts = headers["Strict-Transport-Security"]
            if "max-age=" not in hsts:
                issues.append("HSTS missing max-age directive")
            elif "max-age=0" in hsts:
                issues.append("HSTS max-age set to 0 (disabled)")
        
        # Validate CSP
        if "Content-Security-Policy" in headers:
            csp = headers["Content-Security-Policy"]
            if "unsafe-inline" in csp and "unsafe-eval" in csp:
                issues.append("CSP allows both unsafe-inline and unsafe-eval")
        
        # Validate X-Frame-Options
        if "X-Frame-Options" in headers:
            xfo = headers["X-Frame-Options"]
            if xfo not in ["DENY", "SAMEORIGIN", "ALLOW-FROM"]:
                issues.append(f"Invalid X-Frame-Options value: {xfo}")
        
        return issues


# Global instances
security_headers_middleware = None
security_headers_validator = SecurityHeadersValidator()


def get_security_headers_middleware(app):
    """Get security headers middleware instance"""
    global security_headers_middleware
    if security_headers_middleware is None:
        security_headers_middleware = SecurityHeadersMiddleware(app)
    return security_headers_middleware


def validate_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Validate security headers"""
    return security_headers_validator.validate_headers(headers)


def get_security_headers_stats() -> Dict[str, Any]:
    """Get security headers statistics"""
    if security_headers_middleware:
        return security_headers_middleware.get_header_statistics()
    return {"enabled": False}
