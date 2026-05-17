"""
Enterprise-grade security middleware for FastAPI applications
Implements comprehensive security headers and protections
"""

import os
from typing import Dict, List, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings
from app.core.security_config import Environment


class EnterpriseSecurityMiddleware(BaseHTTPMiddleware):
    """
    Enterprise-grade security middleware implementing:
    - HTTP Strict Transport Security (HSTS)
    - Content Security Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - Referrer-Policy
    - Permissions-Policy
    - Additional security headers
    """
    
    def __init__(self, app, **kwargs):
        super().__init__(app, **kwargs)
        self.environment = settings.ENVIRONMENT
        self.security_config = self._load_security_config()
    
    def _load_security_config(self) -> Dict[str, str]:
        """Load security configuration from environment variables"""
        return {
            # HSTS Configuration
            "hsts_max_age": os.getenv("HSTS_MAX_AGE", "31536000"),  # 1 year
            "hsts_include_subdomains": os.getenv("HSTS_INCLUDE_SUBDOMAINS", "true"),
            "hsts_preload": os.getenv("HSTS_PRELOAD", "true"),
            
            # Production-Safe CSP Configuration
            "csp_default_src": os.getenv("CSP_DEFAULT_SRC", "'self'"),
            "csp_script_src": os.getenv("CSP_SCRIPT_SRC", self._get_script_src_config()),
            "csp_style_src": os.getenv("CSP_STYLE_SRC", self._get_style_src_config()),
            "csp_img_src": os.getenv("CSP_IMG_SRC", "'self' data: https:"),
            "csp_connect_src": os.getenv("CSP_CONNECT_SRC", "'self'"),
            "csp_font_src": os.getenv("CSP_FONT_SRC", "'self'"),
            "csp_object_src": os.getenv("CSP_OBJECT_SRC", "'none'"),
            "csp_media_src": os.getenv("CSP_MEDIA_SRC", "'self'"),
            "csp_frame_src": os.getenv("CSP_FRAME_SRC", "'none'"),
            "csp_frame_ancestors": os.getenv("CSP_FRAME_ANCESTORS", "'none'"),
            "csp_base_uri": os.getenv("CSP_BASE_URI", "'self'"),
            "csp_form_action": os.getenv("CSP_FORM_ACTION", "'self'"),
            
            # Additional Security
            "enable_csp": os.getenv("ENABLE_CSP", "true").lower() == "true",
            "enable_hsts": os.getenv("ENABLE_HSTS", "true").lower() == "true",
        }
    
    def _get_script_src_config(self) -> str:
        """Get script-src configuration based on environment"""
        if self.environment == Environment.DEV:
            # Development: Allow Swagger UI scripts and inline scripts
            return "'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net"
        else:
            # Production: Strict but allow Swagger CDN
            return "'self' https://cdn.jsdelivr.net"
    
    def _get_style_src_config(self) -> str:
        """Get style-src configuration based on environment"""
        if self.environment == Environment.DEV:
            # Development: Allow Swagger UI styles and inline styles
            return "'self' 'unsafe-inline' https://cdn.jsdelivr.net"
        else:
            # Production: Strict but allow Swagger CDN
            return "'self' 'unsafe-inline' https://cdn.jsdelivr.net"
    
    def _get_hsts_header(self) -> Optional[str]:
        """Generate HSTS header based on configuration"""
        if not self.security_config["enable_hsts"] or self.environment != Environment.PROD:
            return None
        
        max_age = self.security_config["hsts_max_age"]
        include_subdomains = self.security_config["hsts_include_subdomains"]
        preload = self.security_config["hsts_preload"]
        
        hsts_parts = [f"max-age={max_age}"]
        
        if include_subdomains.lower() == "true":
            hsts_parts.append("includeSubDomains")
        
        if preload.lower() == "true":
            hsts_parts.append("preload")
        
        return "; ".join(hsts_parts)
    
    def _get_csp_header(self) -> Optional[str]:
        """Generate Content Security Policy header"""
        if not self.security_config["enable_csp"]:
            return None
        
        csp_parts = []
        
        # Build CSP directives with production-safe configuration
        directives = {
            "default-src": self.security_config["csp_default_src"],
            "script-src": self.security_config["csp_script_src"],
            "style-src": self.security_config["csp_style_src"],
            "img-src": self.security_config["csp_img_src"],
            "connect-src": self.security_config["csp_connect_src"],
            "font-src": self.security_config["csp_font_src"],
            "object-src": self.security_config["csp_object_src"],
            "media-src": self.security_config["csp_media_src"],
            "frame-src": self.security_config["csp_frame_src"],
            "frame-ancestors": self.security_config["csp_frame_ancestors"],
            "base-uri": self.security_config["csp_base_uri"],
            "form-action": self.security_config["csp_form_action"],
        }
        
        for directive, value in directives.items():
            if value and value != "'none'":
                csp_parts.append(f"{directive} {value}")
            elif value == "'none'":
                csp_parts.append(f"{directive} {value}")
        
        return "; ".join(csp_parts)
    
    def _get_permissions_policy(self) -> str:
        """Generate Permissions Policy header"""
        # Disable sensitive APIs by default
        permissions = [
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
            "encrypted-media=()",
            "fullscreen=()",
            "picture-in-picture=()",
        ]
        
        return ", ".join(permissions)
    
    def _get_security_headers(self) -> Dict[str, str]:
        """Get all security headers"""
        headers = {}
        
        # Basic security headers (always enabled)
        headers.update({
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-XSS-Protection": "1; mode=block",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        })
        
        # HSTS (production only)
        hsts_header = self._get_hsts_header()
        if hsts_header:
            headers["Strict-Transport-Security"] = hsts_header
        
        # CSP (configurable)
        csp_header = self._get_csp_header()
        if csp_header:
            headers["Content-Security-Policy"] = csp_header
        
        # Permissions Policy
        headers["Permissions-Policy"] = self._get_permissions_policy()
        
        # Additional headers
        headers.update({
            "Server": "Mary-V5-Secure",  # Hide server info
            "X-Request-ID": "auto-generated",  # Will be overridden by tracing middleware
        })
        
        return headers
    
    async def dispatch(self, request: Request, call_next):
        """Apply security headers to all responses"""
        response: Response = await call_next(request)
        
        # Get security headers
        security_headers = self._get_security_headers()
        
        # Apply headers to response
        for header, value in security_headers.items():
            # Don't override existing X-Request-ID from tracing middleware
            if header == "X-Request-ID" and "x-request-id" in response.headers:
                continue
            response.headers[header] = value
        
        return response


class SecurityConfigManager:
    """Manager for security configuration validation"""
    
    @staticmethod
    def validate_csp_directive(directive: str, value: str) -> bool:
        """Validate CSP directive values"""
        valid_sources = [
            "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'",
            "'unsafe-hashes'", "'strict-dynamic'", "data:", "https:", "http:"
        ]
        
        # Basic validation - can be enhanced
        return any(source in value for source in valid_sources) or value.startswith(("https://", "http://"))
    
    @staticmethod
    def get_security_recommendations() -> List[str]:
        """Get security recommendations based on current configuration"""
        recommendations = []
        
        # Check HSTS
        if not os.getenv("ENABLE_HSTS", "true").lower() == "true":
            recommendations.append("Enable HSTS for production")
        
        # Check CSP
        if not os.getenv("ENABLE_CSP", "true").lower() == "true":
            recommendations.append("Enable Content Security Policy")
        
        # Check dangerous CSP values
        csp_script_src = os.getenv("CSP_SCRIPT_SRC", "")
        if "'unsafe-inline'" in csp_script_src or "'unsafe-eval'" in csp_script_src:
            recommendations.append("Review CSP script-src: remove unsafe-inline/unsafe-eval for production")
        
        return recommendations
