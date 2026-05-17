#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Simplified Core Architecture
Consolidated and simplified core functionality for maintainability
"""

import os
import sys
import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass
from collections import defaultdict
import weakref

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging once
def setup_logging():
    """Setup logging with proper path handling"""
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, 'simplified_core.log')),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)


@dataclass
class SystemEvent:
    """Unified system event"""
    event_id: str
    event_type: str
    timestamp: datetime
    source: str
    data: Dict[str, Any]
    severity: str = "info"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'data': self.data,
            'severity': self.severity
        }


class SimpleEventManager:
    """Simplified event management"""
    
    def __init__(self):
        self.events: List[SystemEvent] = []
        self.max_events = 10000
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
        
    def emit(self, event_type: str, source: str, data: Dict[str, Any], severity: str = "info"):
        """Emit event"""
        event = SystemEvent(
            event_id=f"{int(time.time())}_{len(self.events)}",
            event_type=event_type,
            timestamp=datetime.utcnow(),
            source=source,
            data=data,
            severity=severity
        )
        
        # Store event
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)
        
        # Notify subscribers
        for callback in self.subscribers[event_type]:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to events"""
        self.subscribers[event_type].append(callback)
    
    def get_events(self, event_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get events"""
        events = self.events
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return [e.to_dict() for e in events[-limit:]]


class SimpleConfigManager:
    """Simplified configuration management"""
    
    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.config_file = "/app/config/simplified_config.json"
        self.load_config()
    
    def load_config(self):
        """Load configuration"""
        default_config = {
            "system": {
                "name": "MARY V5 SHIELD CORE",
                "version": "5.0.0",
                "environment": "production",
                "debug": False
            },
            "security": {
                "enable_auth": True,
                "session_timeout": 3600,
                "max_login_attempts": 5
            },
            "performance": {
                "max_workers": 10,
                "request_timeout": 30,
                "cache_ttl": 300
            },
            "logging": {
                "level": "INFO",
                "max_file_size": "10MB",
                "backup_count": 5
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                # Merge with defaults
                self._merge_config(default_config, file_config)
            else:
                self.config = default_config
                self.save_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.config = default_config
    
    def _merge_config(self, default: Dict[str, Any], override: Dict[str, Any]):
        """Merge configuration"""
        for key, value in override.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
        self.config = default
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config()
    
    def save_config(self):
        """Save configuration"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving config: {e}")


class SimpleHealthManager:
    """Simplified health management"""
    
    def __init__(self, event_manager: SimpleEventManager):
        self.event_manager = event_manager
        self.services: Dict[str, Dict[str, Any]] = {}
        self.health_checks: Dict[str, Callable] = {}
        
    def register_service(self, name: str, health_check: Callable):
        """Register service with health check"""
        self.services[name] = {
            'name': name,
            'status': 'unknown',
            'last_check': None,
            'error_count': 0
        }
        self.health_checks[name] = health_check
    
    async def check_health(self, service_name: str) -> Dict[str, Any]:
        """Check service health"""
        if service_name not in self.health_checks:
            return {'status': 'unknown', 'error': 'Service not found'}
        
        try:
            result = await self.health_checks[service_name]()
            service = self.services[service_name]
            
            service['status'] = result.get('status', 'unknown')
            service['last_check'] = datetime.utcnow()
            service['error_count'] = 0
            
            # Emit health event
            self.event_manager.emit(
                'health_check',
                service_name,
                {
                    'status': service['status'],
                    'details': result
                },
                'info'
            )
            
            return result
            
        except Exception as e:
            service = self.services[service_name]
            service['status'] = 'error'
            service['last_check'] = datetime.utcnow()
            service['error_count'] += 1
            
            # Emit error event
            self.event_manager.emit(
                'health_check',
                service_name,
                {
                    'status': 'error',
                    'error': str(e)
                },
                'error'
            )
            
            return {'status': 'error', 'error': str(e)}
    
    async def check_all_health(self) -> Dict[str, Any]:
        """Check all services health"""
        results = {}
        for service_name in self.services:
            results[service_name] = await self.check_health(service_name)
        
        return results
    
    def get_service_status(self, service_name: str) -> Dict[str, Any]:
        """Get service status"""
        if service_name not in self.services:
            return {'status': 'unknown', 'error': 'Service not found'}
        
        service = self.services[service_name]
        return {
            'name': service['name'],
            'status': service['status'],
            'last_check': service['last_check'].isoformat() if service['last_check'] else None,
            'error_count': service['error_count']
        }


class SimpleCacheManager:
    """Simplified cache management"""
    
    def __init__(self, event_manager: SimpleEventManager):
        self.event_manager = event_manager
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = 300  # 5 minutes
        
    def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        if key not in self.cache:
            return None
        
        entry = self.cache[key]
        if datetime.utcnow() > entry['expires']:
            del self.cache[key]
            return None
        
        return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set cached value"""
        expires = datetime.utcnow() + timedelta(seconds=ttl or self.default_ttl)
        self.cache[key] = {
            'value': value,
            'expires': expires
        }
        
        # Emit cache event
        self.event_manager.emit(
            'cache_set',
            'cache_manager',
            {'key': key, 'ttl': ttl or self.default_ttl},
            'debug'
        )
    
    def delete(self, key: str):
        """Delete cached value"""
        if key in self.cache:
            del self.cache[key]
            
            # Emit cache event
            self.event_manager.emit(
                'cache_delete',
                'cache_manager',
                {'key': key},
                'debug'
            )
    
    def clear(self):
        """Clear all cache"""
        self.cache.clear()
        
        # Emit cache event
        self.event_manager.emit(
            'cache_clear',
            'cache_manager',
            {},
            'debug'
        )
    
    def cleanup(self):
        """Clean up expired entries"""
        now = datetime.utcnow()
        expired_keys = [k for k, v in self.cache.items() if now > v['expires']]
        
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            self.event_manager.emit(
                'cache_cleanup',
                'cache_manager',
                {'expired_count': len(expired_keys)},
                'debug'
            )


class SimpleSecurityManager:
    """Simplified security management"""
    
    def __init__(self, event_manager: SimpleEventManager, config_manager: SimpleConfigManager):
        self.event_manager = event_manager
        self.config = config_manager
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.login_attempts: Dict[str, int] = defaultdict(int)
        
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user"""
        # Simple authentication logic
        if self.login_attempts[username] >= self.config.get('security.max_login_attempts', 5):
            return {'success': False, 'error': 'Too many login attempts'}
        
        # In real implementation, verify against database
        if username == 'admin' and password == 'admin':
            self.login_attempts[username] = 0
            session_id = f"session_{int(time.time())}_{username}"
            
            self.sessions[session_id] = {
                'username': username,
                'created_at': datetime.utcnow(),
                'last_activity': datetime.utcnow()
            }
            
            # Emit auth event
            self.event_manager.emit(
                'user_login',
                'security_manager',
                {'username': username, 'session_id': session_id},
                'info'
            )
            
            return {'success': True, 'session_id': session_id}
        else:
            self.login_attempts[username] += 1
            
            # Emit auth event
            self.event_manager.emit(
                'login_failed',
                'security_manager',
                {'username': username, 'attempts': self.login_attempts[username]},
                'warning'
            )
            
            return {'success': False, 'error': 'Invalid credentials'}
    
    def validate_session(self, session_id: str) -> bool:
        """Validate session"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        timeout = self.config.get('security.session_timeout', 3600)
        
        if datetime.utcnow() - session['last_activity'] > timedelta(seconds=timeout):
            del self.sessions[session_id]
            return False
        
        # Update last activity
        session['last_activity'] = datetime.utcnow()
        return True
    
    def logout(self, session_id: str):
        """Logout user"""
        if session_id in self.sessions:
            username = self.sessions[session_id]['username']
            del self.sessions[session_id]
            
            # Emit auth event
            self.event_manager.emit(
                'user_logout',
                'security_manager',
                {'username': username, 'session_id': session_id},
                'info'
            )


class SimplePerformanceManager:
    """Simplified performance management"""
    
    def __init__(self, event_manager: SimpleEventManager):
        self.event_manager = event_manager
        self.metrics: Dict[str, List[float]] = defaultdict(list)
        self.max_metrics = 1000
        
    def record_metric(self, metric_name: str, value: float):
        """Record performance metric"""
        self.metrics[metric_name].append(value)
        
        # Keep only recent metrics
        if len(self.metrics[metric_name]) > self.max_metrics:
            self.metrics[metric_name].pop(0)
        
        # Emit metric event
        self.event_manager.emit(
            'performance_metric',
            'performance_manager',
            {'metric': metric_name, 'value': value},
            'debug'
        )
    
    def get_metric_stats(self, metric_name: str) -> Dict[str, float]:
        """Get metric statistics"""
        if metric_name not in self.metrics or not self.metrics[metric_name]:
            return {'count': 0, 'avg': 0.0, 'min': 0.0, 'max': 0.0}
        
        values = self.metrics[metric_name]
        return {
            'count': len(values),
            'avg': sum(values) / len(values),
            'min': min(values),
            'max': max(values)
        }
    
    def get_all_metrics(self) -> Dict[str, Dict[str, float]]:
        """Get all metrics"""
        return {name: self.get_metric_stats(name) for name in self.metrics}


class SimplifiedCore:
    """Simplified core system"""
    
    def __init__(self):
        """Initialize simplified core"""
        self.event_manager = SimpleEventManager()
        self.config_manager = SimpleConfigManager()
        self.health_manager = SimpleHealthManager(self.event_manager)
        self.cache_manager = SimpleCacheManager(self.event_manager)
        self.security_manager = SimpleSecurityManager(self.event_manager, self.config_manager)
        self.performance_manager = SimplePerformanceManager(self.event_manager)
        
        self.is_running = False
        self.start_time = None
        
        # Setup event subscriptions
        self._setup_event_subscriptions()
        
        logger.info("Simplified core initialized")
    
    def _setup_event_subscriptions(self):
        """Setup event subscriptions"""
        # Subscribe to error events
        self.event_manager.subscribe('error', self._handle_error_event)
        self.event_manager.subscribe('health_check', self._handle_health_event)
        self.event_manager.subscribe('user_login', self._handle_auth_event)
        self.event_manager.subscribe('user_logout', self._handle_auth_event)
    
    def _handle_error_event(self, event: SystemEvent):
        """Handle error events"""
        logger.error(f"Error event: {event.event_type} - {event.data}")
    
    def _handle_health_event(self, event: SystemEvent):
        """Handle health events"""
        if event.data.get('status') == 'error':
            logger.warning(f"Health check failed: {event.source}")
    
    def _handle_auth_event(self, event: SystemEvent):
        """Handle authentication events"""
        logger.info(f"Auth event: {event.event_type} - {event.data.get('username', 'unknown')}")
    
    async def start(self):
        """Start core system"""
        logger.info("Starting simplified core")
        
        self.start_time = datetime.utcnow()
        self.is_running = True
        
        # Emit start event
        self.event_manager.emit(
            'system_start',
            'core',
            {'start_time': self.start_time.isoformat()},
            'info'
        )
        
        # Start background tasks
        asyncio.create_task(self._background_tasks())
        
        logger.info("Simplified core started successfully")
    
    async def stop(self):
        """Stop core system"""
        logger.info("Stopping simplified core")
        
        self.is_running = False
        
        # Emit stop event
        self.event_manager.emit(
            'system_stop',
            'core',
            {'stop_time': datetime.utcnow().isoformat()},
            'info'
        )
        
        # Cleanup
        self.cache_manager.clear()
        
        logger.info("Simplified core stopped successfully")
    
    async def _background_tasks(self):
        """Background tasks"""
        while self.is_running:
            try:
                # Cleanup expired cache entries
                self.cache_manager.cleanup()
                
                # Check system health
                await self.health_manager.check_all_health()
                
                # Wait for next iteration
                await asyncio.sleep(60)  # 1 minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in background tasks: {e}")
                await asyncio.sleep(10)
    
    def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        uptime = (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'is_running': self.is_running,
            'uptime': uptime,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'config': {
                'name': self.config_manager.get('system.name'),
                'version': self.config_manager.get('system.version'),
                'environment': self.config_manager.get('system.environment')
            },
            'services': {
                name: self.health_manager.get_service_status(name)
                for name in self.health_manager.services
            },
            'cache': {
                'size': len(self.cache_manager.cache),
                'max_size': self.cache_manager.max_events
            },
            'sessions': {
                'active': len(self.security_manager.sessions),
                'max_age': self.config_manager.get('security.session_timeout')
            },
            'metrics': self.performance_manager.get_all_metrics()
        }
    
    def get_events(self, event_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get events"""
        return self.event_manager.get_events(event_type, limit)


# Global simplified core instance
simplified_core = SimplifiedCore()


# API functions
async def initialize_simplified_core() -> str:
    """Initialize simplified core"""
    try:
        await simplified_core.start()
        logger.info("Simplified core initialized")
        return "Simplified core initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing simplified core: {e}")
        return f"Error initializing simplified core: {e}"


async def stop_simplified_core() -> str:
    """Stop simplified core"""
    try:
        await simplified_core.stop()
        logger.info("Simplified core stopped")
        return "Simplified core stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping simplified core: {e}")
        return f"Error stopping simplified core: {e}"


def get_core_status() -> Dict[str, Any]:
    """Get core status"""
    try:
        return simplified_core.get_status()
    except Exception as e:
        logger.error(f"Error getting core status: {e}")
        return {'error': str(e)}


def get_core_events(event_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Get core events"""
    try:
        return simplified_core.get_events(event_type, limit)
    except Exception as e:
        logger.error(f"Error getting core events: {e}")
        return []


# Initialize simplified core
async def initialize_core_system() -> str:
    """Initialize core system"""
    try:
        await initialize_simplified_core()
        logger.info("Core system initialized")
        return "Core system initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing core system: {e}")
        return f"Error initializing core system: {e}"


# Cleanup function
async def cleanup_core_system() -> str:
    """Cleanup core system"""
    try:
        await stop_simplified_core()
        logger.info("Core system cleaned up")
        return "Core system cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up core system: {e}")
        return f"Error cleaning up core system: {e}"
