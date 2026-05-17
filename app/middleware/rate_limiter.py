"""
Enterprise-grade rate limiting middleware for FastAPI
Implements IP-based and user-based rate limiting with Redis backend
"""

import os
import time
import asyncio
from typing import Dict, Optional, Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi import status

from app.core.dependencies import logger


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Enterprise rate limiting middleware with:
    - IP-based limiting
    - User-based limiting (when authenticated)
    - Redis backend for distributed systems
    - Configurable limits per endpoint
    - Sliding window implementation
    """
    
    def __init__(self, app, **kwargs):
        super().__init__(app, **kwargs)
        self.limits = self._load_rate_limits()
        self.redis_available = False
        self.redis_client = None
        self.memory_store = {}
    
    def _load_rate_limits(self) -> Dict[str, str]:
        """Load rate limit configuration from environment"""
        return {
            # Global limits
            "global": os.getenv("RATE_LIMIT_GLOBAL", "1000/minute"),
            
            # Endpoint-specific limits
            "auth": os.getenv("RATE_LIMIT_AUTH", "5/minute"),
            "login": os.getenv("RATE_LIMIT_LOGIN", "3/minute"),
            "admin": os.getenv("RATE_LIMIT_ADMIN", "50/minute"),
            "api": os.getenv("RATE_LIMIT_API", "100/minute"),
            "health": os.getenv("RATE_LIMIT_HEALTH", "200/minute"),
            
            # Sensitive operations
            "password_reset": os.getenv("RATE_LIMIT_PASSWORD_RESET", "3/hour"),
            "token_refresh": os.getenv("RATE_LIMIT_TOKEN_REFRESH", "10/minute"),
        }
    
    async def _init_redis_backend(self):
        """Initialize Redis backend for distributed rate limiting"""
        try:
            # Try to import and use Redis for distributed rate limiting
            from app.infrastructure.redis import get_redis_client
            self.redis_client = await get_redis_client()
            self.redis_available = True
            logger.info("Rate limiting: Redis backend initialized")
        except Exception as e:
            logger.warning(f"Rate limiting: Using in-memory backend (Redis unavailable): {e}")
            self.redis_available = False
            self.memory_store = {}
    
    def _parse_rate_limit(self, limit_str: str) -> Tuple[int, int]:
        """Parse rate limit string like "5/minute" to (5, 60)"""
        try:
            count, period = limit_str.split("/")
            count = int(count)
            
            # Convert period to seconds
            period_map = {
                "second": 1, "seconds": 1,
                "minute": 60, "minutes": 60,
                "hour": 3600, "hours": 3600,
                "day": 86400, "days": 86400
            }
            
            period_seconds = period_map.get(period.lower(), 60)
            return count, period_seconds
        except Exception:
            return 100, 60  # Safe default
    
    def _get_limit_key(self, request: Request, limit_type: str) -> str:
        """Generate rate limit key based on request"""
        # Try to get user ID from request state (set by auth middleware)
        user_id = getattr(request.state, 'user_id', None)
        
        if user_id:
            # User-based limiting for authenticated requests
            return f"rate_limit:user:{user_id}:{limit_type}"
        else:
            # IP-based limiting for unauthenticated requests
            client_ip = self._get_client_ip(request)
            return f"rate_limit:ip:{client_ip}:{limit_type}"
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP from request, considering proxies"""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fallback to client IP
        if hasattr(request, 'client') and request.client:
            return request.client.host
        
        return "unknown"
    
    def _get_endpoint_category(self, path: str, method: str) -> str:
        """Categorize endpoint for rate limiting"""
        path_lower = path.lower()
        
        # Authentication endpoints
        if "/auth/" in path_lower or "/login" in path_lower:
            if "login" in path_lower or "token" in path_lower:
                return "login"
            return "auth"
        
        # Admin endpoints
        if "/admin" in path_lower:
            return "admin"
        
        # Health endpoints
        if "/health" in path_lower:
            return "health"
        
        # Password reset
        if "password" in path_lower and "reset" in path_lower:
            return "password_reset"
        
        # Token refresh
        if "refresh" in path_lower and "token" in path_lower:
            return "token_refresh"
        
        # Default API limit
        return "api"
    
    async def _check_rate_limit_redis(self, key: str, limit: int, period: int) -> Tuple[bool, Dict]:
        """Check rate limit using Redis backend"""
        try:
            current_time = int(time.time())
            window_start = current_time - period
            
            # Use Redis sliding window
            pipeline = self.redis_client.pipeline()
            
            # Remove old entries
            pipeline.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            pipeline.zcard(key)
            
            # Add current request
            pipeline.zadd(key, {str(current_time): current_time})
            
            # Set expiration
            pipeline.expire(key, period)
            
            results = await pipeline.execute()
            current_count = results[1]
            
            is_allowed = current_count < limit
            ttl = await self.redis_client.ttl(key)
            
            return is_allowed, {
                "limit": limit,
                "remaining": max(0, limit - current_count),
                "reset_time": current_time + ttl,
                "retry_after": ttl if not is_allowed else 0
            }
            
        except Exception as e:
            logger.error(f"Rate limiting Redis error: {e}")
            # Fallback to memory store
            return await self._check_rate_limit_memory(key, limit, period)
    
    async def _check_rate_limit_memory(self, key: str, limit: int, period: int) -> Tuple[bool, Dict]:
        """Check rate limit using in-memory store (fallback)"""
        current_time = int(time.time())
        window_start = current_time - period
        
        # Initialize key if not exists
        if key not in self.memory_store:
            self.memory_store[key] = []
        
        # Remove old entries
        self.memory_store[key] = [
            timestamp for timestamp in self.memory_store[key]
            if timestamp > window_start
        ]
        
        # Check current count
        current_count = len(self.memory_store[key])
        
        if current_count < limit:
            self.memory_store[key].append(current_time)
            return True, {
                "limit": limit,
                "remaining": limit - current_count - 1,
                "reset_time": current_time + period,
                "retry_after": 0
            }
        
        # Rate limited
        oldest_request = min(self.memory_store[key]) if self.memory_store[key] else current_time
        retry_after = max(0, oldest_request + period - current_time)
        
        return False, {
            "limit": limit,
            "remaining": 0,
            "reset_time": current_time + period,
            "retry_after": retry_after
        }
    
    async def dispatch(self, request: Request, call_next):
        """Apply rate limiting to requests"""
        # Initialize Redis if not done yet
        if not self.redis_available and self.redis_client is None:
            await self._init_redis_backend()
        
        # Get endpoint category and corresponding limit
        endpoint_category = self._get_endpoint_category(request.url.path, request.method)
        limit_str = self.limits.get(endpoint_category, self.limits["global"])
        limit, period = self._parse_rate_limit(limit_str)
        
        # Generate rate limit key
        limit_key = self._get_limit_key(request, endpoint_category)
        
        # Check rate limit
        if self.redis_available:
            is_allowed, limit_info = await self._check_rate_limit_redis(limit_key, limit, period)
        else:
            is_allowed, limit_info = await self._check_rate_limit_memory(limit_key, limit, period)
        
        # Add rate limit headers
        response = await call_next(request)
        response.headers.update({
            "X-RateLimit-Limit": str(limit_info["limit"]),
            "X-RateLimit-Remaining": str(limit_info["remaining"]),
            "X-RateLimit-Reset": str(limit_info["reset_time"]),
        })
        
        # Return 429 if rate limited
        if not is_allowed:
            logger.warning(
                "Rate limit exceeded",
                key=limit_key,
                endpoint=request.url.path,
                method=request.method,
                retry_after=limit_info["retry_after"]
            )
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": limit_info["retry_after"],
                    "limit": limit_info["limit"],
                    "reset_time": limit_info["reset_time"]
                },
                headers={
                    "Retry-After": str(limit_info["retry_after"]),
                    "X-RateLimit-Limit": str(limit_info["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(limit_info["reset_time"]),
                }
            )
        
        return response


class RateLimitConfig:
    """Configuration manager for rate limiting"""
    
    @staticmethod
    def get_environment_config() -> Dict[str, str]:
        """Get rate limit configuration for current environment"""
        return {
            "RATE_LIMIT_GLOBAL": os.getenv("RATE_LIMIT_GLOBAL", "1000/minute"),
            "RATE_LIMIT_AUTH": os.getenv("RATE_LIMIT_AUTH", "5/minute"),
            "RATE_LIMIT_LOGIN": os.getenv("RATE_LIMIT_LOGIN", "3/minute"),
            "RATE_LIMIT_ADMIN": os.getenv("RATE_LIMIT_ADMIN", "50/minute"),
            "RATE_LIMIT_API": os.getenv("RATE_LIMIT_API", "100/minute"),
            "RATE_LIMIT_HEALTH": os.getenv("RATE_LIMIT_HEALTH", "200/minute"),
            "RATE_LIMIT_PASSWORD_RESET": os.getenv("RATE_LIMIT_PASSWORD_RESET", "3/hour"),
            "RATE_LIMIT_TOKEN_REFRESH": os.getenv("RATE_LIMIT_TOKEN_REFRESH", "10/minute"),
        }
    
    @staticmethod
    def validate_rate_limit_config() -> list:
        """Validate rate limit configuration"""
        issues = []
        config = RateLimitConfig.get_environment_config()
        
        for key, value in config.items():
            try:
                count, period = value.split("/")
                count = int(count)
                period_map = {
                    "second": 1, "seconds": 1,
                    "minute": 60, "minutes": 60,
                    "hour": 3600, "hours": 3600,
                    "day": 86400, "days": 86400
                }
                
                if period.lower() not in period_map:
                    issues.append(f"Invalid period in {key}: {period}")
                
                if count <= 0:
                    issues.append(f"Invalid count in {key}: {count}")
                    
            except Exception:
                issues.append(f"Invalid format for {key}: {value}")
        
        return issues
