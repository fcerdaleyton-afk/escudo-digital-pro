#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Simplified API Layer
Consolidated API with reduced complexity and improved maintainability
"""

import os
import sys
import asyncio
import logging
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.simplified_core import simplified_core, SystemEvent

# Configure API logging
api_logger = logging.getLogger('simplified_api')


@dataclass
class APIResponse:
    """Unified API response"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'timestamp': self.timestamp
        }


class SimplifiedAPI:
    """Simplified API handler"""
    
    def __init__(self):
        self.core = simplified_core
        self.routes: Dict[str, Callable] = {}
        self.middleware: List[Callable] = []
        self.setup_routes()
        self.setup_middleware()
    
    def setup_routes(self):
        """Setup API routes"""
        # System routes
        self.routes['GET /status'] = self.get_status
        self.routes['GET /health'] = self.get_health
        self.routes['GET /events'] = self.get_events
        self.routes['POST /shutdown'] = self.shutdown_system
        
        # Configuration routes
        self.routes['GET /config'] = self.get_config
        self.routes['POST /config'] = self.set_config
        
        # Security routes
        self.routes['POST /auth/login'] = self.login
        self.routes['POST /auth/logout'] = self.logout
        self.routes['GET /auth/validate'] = self.validate_session
        
        # Cache routes
        self.routes['GET /cache'] = self.get_cache
        self.routes['POST /cache'] = self.set_cache
        self.routes['DELETE /cache'] = self.delete_cache
        self.routes['DELETE /cache/clear'] = self.clear_cache
        
        # Performance routes
        self.routes['GET /metrics'] = self.get_metrics
        self.routes['POST /metrics'] = self.record_metric
    
    def setup_middleware(self):
        """Setup middleware"""
        self.middleware = [
            self._logging_middleware,
            self._auth_middleware,
            self._cors_middleware
        ]
    
    async def handle_request(self, method: str, path: str, data: Dict[str, Any] = None, 
                           headers: Dict[str, str] = None) -> APIResponse:
        """Handle API request"""
        try:
            # Find route
            route_key = f"{method} {path}"
            if route_key not in self.routes:
                return APIResponse(success=False, error="Route not found")
            
            # Apply middleware
            request_data = {
                'method': method,
                'path': path,
                'data': data or {},
                'headers': headers or {}
            }
            
            for middleware in self.middleware:
                result = await middleware(request_data)
                if not result.get('success', True):
                    return APIResponse(success=False, error=result.get('error', 'Middleware error'))
            
            # Execute route
            handler = self.routes[route_key]
            response = await handler(request_data)
            
            return response
            
        except Exception as e:
            api_logger.error(f"Error handling request {method} {path}: {e}")
            return APIResponse(success=False, error=str(e))
    
    async def _logging_middleware(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Logging middleware"""
        api_logger.info(f"API Request: {request_data['method']} {request_data['path']}")
        return {'success': True}
    
    async def _auth_middleware(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Authentication middleware"""
        # Skip auth for public routes
        public_routes = ['/status', '/health', '/auth/login', '/metrics']
        if request_data['path'] in public_routes:
            return {'success': True}
        
        # Validate session
        session_id = request_data['headers'].get('Authorization')
        if not session_id:
            return {'success': False, 'error': 'Authorization required'}
        
        if not self.core.security_manager.validate_session(session_id):
            return {'success': False, 'error': 'Invalid session'}
        
        return {'success': True}
    
    async def _cors_middleware(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """CORS middleware"""
        # Simple CORS handling
        return {'success': True}
    
    # Route handlers
    async def get_status(self, request_data: Dict[str, Any]) -> APIResponse:
        """Get system status"""
        try:
            status = self.core.get_status()
            return APIResponse(success=True, data=status)
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def get_health(self, request_data: Dict[str, Any]) -> APIResponse:
        """Get system health"""
        try:
            health = await self.core.health_manager.check_all_health()
            return APIResponse(success=True, data=health)
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def get_events(self, request_data: Dict[str, Any]) -> APIResponse:
        """Get system events"""
        try:
            event_type = request_data['data'].get('event_type')
            limit = request_data['data'].get('limit', 100)
            
            events = self.core.get_events(event_type, limit)
            return APIResponse(success=True, data=events)
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def shutdown_system(self, request_data: Dict[str, Any]) -> APIResponse:
        """Shutdown system"""
        try:
            await self.core.stop()
            return APIResponse(success=True, data={'message': 'System shutdown successfully'})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def get_config(self, request_data: Dict[str, Any]) -> APIResponse:
        """Get configuration"""
        try:
            key = request_data['data'].get('key')
            if key:
                value = self.core.config_manager.get(key)
                return APIResponse(success=True, data={key: value})
            else:
                return APIResponse(success=True, data=self.core.config_manager.config)
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def set_config(self, request_data: Dict[str, Any]) -> APIResponse:
        """Set configuration"""
        try:
            key = request_data['data'].get('key')
            value = request_data['data'].get('value')
            
            if not key:
                return APIResponse(success=False, error='Key required')
            
            self.core.config_manager.set(key, value)
            return APIResponse(success=True, data={'message': 'Configuration updated'})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def login(self, request_data: Dict[str, Any]) -> APIResponse:
        """User login"""
        try:
            username = request_data['data'].get('username')
            password = request_data['data'].get('password')
            
            if not username or not password:
                return APIResponse(success=False, error='Username and password required')
            
            result = self.core.security_manager.authenticate(username, password)
            return APIResponse(success=result['success'], data=result)
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def logout(self, request_data: Dict[str, Any]) -> APIResponse:
        """User logout"""
        try:
            session_id = request_data['headers'].get('Authorization')
            if session_id:
                self.core.security_manager.logout(session_id)
            
            return APIResponse(success=True, data={'message': 'Logged out successfully'})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def validate_session(self, request_data: Dict[str, Any]) -> APIResponse:
        """Validate session"""
        try:
            session_id = request_data['headers'].get('Authorization')
            if not session_id:
                return APIResponse(success=False, error='Session ID required')
            
            is_valid = self.core.security_manager.validate_session(session_id)
            return APIResponse(success=True, data={'valid': is_valid})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def get_cache(self, request_data: Dict[str, Any]) -> APIResponse:
        """Get cache value"""
        try:
            key = request_data['data'].get('key')
            if not key:
                return APIResponse(success=False, error='Key required')
            
            value = self.core.cache_manager.get(key)
            return APIResponse(success=True, data={'key': key, 'value': value})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def set_cache(self, request_data: Dict[str, Any]) -> APIResponse:
        """Set cache value"""
        try:
            key = request_data['data'].get('key')
            value = request_data['data'].get('value')
            ttl = request_data['data'].get('ttl')
            
            if not key:
                return APIResponse(success=False, error='Key required')
            
            self.core.cache_manager.set(key, value, ttl)
            return APIResponse(success=True, data={'message': 'Cache set successfully'})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def delete_cache(self, request_data: Dict[str, Any]) -> APIResponse:
        """Delete cache value"""
        try:
            key = request_data['data'].get('key')
            if not key:
                return APIResponse(success=False, error='Key required')
            
            self.core.cache_manager.delete(key)
            return APIResponse(success=True, data={'message': 'Cache deleted successfully'})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def clear_cache(self, request_data: Dict[str, Any]) -> APIResponse:
        """Clear all cache"""
        try:
            self.core.cache_manager.clear()
            return APIResponse(success=True, data={'message': 'Cache cleared successfully'})
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def get_metrics(self, request_data: Dict[str, Any]) -> APIResponse:
        """Get performance metrics"""
        try:
            metrics = self.core.performance_manager.get_all_metrics()
            return APIResponse(success=True, data=metrics)
        except Exception as e:
            return APIResponse(success=False, error=str(e))
    
    async def record_metric(self, request_data: Dict[str, Any]) -> APIResponse:
        """Record performance metric"""
        try:
            metric_name = request_data['data'].get('name')
            value = request_data['data'].get('value')
            
            if not metric_name or value is None:
                return APIResponse(success=False, error='Name and value required')
            
            self.core.performance_manager.record_metric(metric_name, float(value))
            return APIResponse(success=True, data={'message': 'Metric recorded successfully'})
        except Exception as e:
            return APIResponse(success=False, error=str(e))


# Global simplified API instance
simplified_api = SimplifiedAPI()


# FastAPI integration functions
async def handle_api_request(method: str, path: str, data: Dict[str, Any] = None, 
                           headers: Dict[str, str] = None) -> Dict[str, Any]:
    """Handle API request (FastAPI compatible)"""
    response = await simplified_api.handle_request(method, path, data, headers)
    return response.to_dict()


# Initialize simplified API
async def initialize_simplified_api() -> str:
    """Initialize simplified API"""
    try:
        api_logger.info("Simplified API initialized")
        return "Simplified API initialized successfully"
    except Exception as e:
        api_logger.error(f"Error initializing simplified API: {e}")
        return f"Error initializing simplified API: {e}"


# Cleanup function
async def cleanup_simplified_api() -> str:
    """Cleanup simplified API"""
    try:
        api_logger.info("Simplified API cleaned up")
        return "Simplified API cleaned up successfully"
    except Exception as e:
        api_logger.error(f"Error cleaning up simplified API: {e}")
        return f"Error cleaning up simplified API: {e}"
