#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Enterprise UI Layer
Real-time dashboards with animated threat feeds and dark cyber theme
"""

import os
import sys
import asyncio
import logging
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import weakref

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/enterprise_ui.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class UserRole(Enum):
    """User role enumeration"""
    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SECURITY_OFFICER = "security_officer"
    COMPLIANCE_OFFICER = "compliance_officer"


class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SystemStatus(Enum):
    """System status enumeration"""
    HEALTHY = "healthy"
    WARNING = "warning"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    OFFLINE = "offline"


@dataclass
class UIComponent:
    """UI component data structure"""
    component_id: str
    component_type: str
    title: str
    position: Dict[str, Any]
    size: Dict[str, Any]
    data: Dict[str, Any]
    config: Dict[str, Any]
    last_updated: datetime
    is_visible: bool = True
    is_enabled: bool = True


@dataclass
class ThreatFeedItem:
    """Threat feed item data structure"""
    item_id: str
    threat_type: str
    threat_level: ThreatLevel
    title: str
    description: str
    source_ip: str
    target_user: Optional[str]
    timestamp: datetime
    details: Dict[str, Any]
    is_resolved: bool = False
    assigned_to: Optional[str] = None


@dataclass
class HealthCard:
    """Health card data structure"""
    card_id: str
    service_name: str
    status: SystemStatus
    health_score: float
    metrics: Dict[str, Any]
    last_check: datetime
    alerts: List[Dict[str, Any]]
    uptime: float
    response_time: float


@dataclass
class DashboardWidget:
    """Dashboard widget data structure"""
    widget_id: str
    widget_type: str
    title: str
    data: Dict[str, Any]
    config: Dict[str, Any]
    position: Dict[str, int]
    size: Dict[str, int]
    refresh_interval: int
    last_refresh: datetime


class RealTimeDashboard:
    """Real-time dashboard system"""
    
    def __init__(self):
        """Initialize real-time dashboard"""
        self.widgets: Dict[str, DashboardWidget] = {}
        self.components: Dict[str, UIComponent] = {}
        self.websocket_connections: Dict[str, Any] = {}
        self.update_interval: int = 5  # seconds
        self.is_running: bool = False
        
        # Dashboard configuration
        self.dashboard_config = {
            'theme': 'dark_cyber',
            'auto_refresh': True,
            'animation_enabled': True,
            'sound_enabled': False,
            'notifications_enabled': True
        }
        
        logger.info("Real-time dashboard initialized")
    
    async def start(self):
        """Start real-time dashboard"""
        logger.info("Starting real-time dashboard")
        
        # Initialize default widgets
        await self._initialize_default_widgets()
        
        # Start update loop
        asyncio.create_task(self._update_loop())
        
        self.is_running = True
        logger.info("Real-time dashboard started")
    
    async def stop(self):
        """Stop real-time dashboard"""
        logger.info("Stopping real-time dashboard")
        
        self.is_running = False
        
        # Close WebSocket connections
        for connection_id, websocket in self.websocket_connections.items():
            try:
                await websocket.close()
            except:
                pass
        
        logger.info("Real-time dashboard stopped")
    
    async def _initialize_default_widgets(self):
        """Initialize default dashboard widgets"""
        try:
            # System overview widget
            self.widgets['system_overview'] = DashboardWidget(
                widget_id='system_overview',
                widget_type='system_overview',
                title='System Overview',
                data={},
                config={'refresh_rate': 5},
                position={'x': 0, 'y': 0},
                size={'width': 12, 'height': 6},
                refresh_interval=5,
                last_refresh=datetime.utcnow()
            )
            
            # Threat feed widget
            self.widgets['threat_feed'] = DashboardWidget(
                widget_id='threat_feed',
                widget_type='threat_feed',
                title='Live Threat Feed',
                data={},
                config={'refresh_rate': 2, 'max_items': 50},
                position={'x': 0, 'y': 6},
                size={'width': 8, 'height': 8},
                refresh_interval=2,
                last_refresh=datetime.utcnow()
            )
            
            # System health widget
            self.widgets['system_health'] = DashboardWidget(
                widget_id='system_health',
                widget_type='system_health',
                title='System Health',
                data={},
                config={'refresh_rate': 10},
                position={'x': 8, 'y': 6},
                size={'width': 4, 'height': 8},
                refresh_interval=10,
                last_refresh=datetime.utcnow()
            )
            
            # Performance metrics widget
            self.widgets['performance_metrics'] = DashboardWidget(
                widget_id='performance_metrics',
                widget_type='performance_metrics',
                title='Performance Metrics',
                data={},
                config={'refresh_rate': 5},
                position={'x': 0, 'y': 14},
                size={'width': 6, 'height': 6},
                refresh_interval=5,
                last_refresh=datetime.utcnow()
            )
            
            # Security metrics widget
            self.widgets['security_metrics'] = DashboardWidget(
                widget_id='security_metrics',
                widget_type='security_metrics',
                title='Security Metrics',
                data={},
                config={'refresh_rate': 5},
                position={'x': 6, 'y': 14},
                size={'width': 6, 'height': 6},
                refresh_interval=5,
                last_refresh=datetime.utcnow()
            )
            
            logger.info("Default widgets initialized")
            
        except Exception as e:
            logger.error(f"Error initializing default widgets: {e}")
    
    async def _update_loop(self):
        """Main update loop"""
        while self.is_running:
            try:
                # Update all widgets
                await self._update_all_widgets()
                
                # Broadcast updates to WebSocket clients
                await self._broadcast_updates()
                
                # Wait for next update
                await asyncio.sleep(self.update_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in update loop: {e}")
                await asyncio.sleep(5)
    
    async def _update_all_widgets(self):
        """Update all dashboard widgets"""
        try:
            for widget_id, widget in self.widgets.items():
                try:
                    await self._update_widget(widget)
                    widget.last_refresh = datetime.utcnow()
                except Exception as e:
                    logger.error(f"Error updating widget {widget_id}: {e}")
            
        except Exception as e:
            logger.error(f"Error updating all widgets: {e}")
    
    async def _update_widget(self, widget: DashboardWidget):
        """Update individual widget"""
        try:
            if widget.widget_type == 'system_overview':
                await self._update_system_overview(widget)
            elif widget.widget_type == 'threat_feed':
                await self._update_threat_feed(widget)
            elif widget.widget_type == 'system_health':
                await self._update_system_health(widget)
            elif widget.widget_type == 'performance_metrics':
                await self._update_performance_metrics(widget)
            elif widget.widget_type == 'security_metrics':
                await self._update_security_metrics(widget)
            
        except Exception as e:
            logger.error(f"Error updating widget {widget.widget_id}: {e}")
    
    async def _update_system_overview(self, widget: DashboardWidget):
        """Update system overview widget"""
        try:
            # Simulate system overview data
            widget.data = {
                'total_threats': 156,
                'active_threats': 23,
                'critical_threats': 3,
                'system_status': 'healthy',
                'uptime': 99.97,
                'last_update': datetime.utcnow().isoformat(),
                'services': {
                    'api': {'status': 'healthy', 'response_time': 45},
                    'database': {'status': 'healthy', 'response_time': 12},
                    'cache': {'status': 'healthy', 'response_time': 2},
                    'websocket': {'status': 'healthy', 'response_time': 8}
                }
            }
            
        except Exception as e:
            logger.error(f"Error updating system overview: {e}")
    
    async def _update_threat_feed(self, widget: DashboardWidget):
        """Update threat feed widget"""
        try:
            # Simulate threat feed data
            threats = []
            for i in range(10):
                threat = ThreatFeedItem(
                    item_id=f"threat_{int(time.time())}_{i}",
                    threat_type=random.choice(['malware', 'phishing', 'ddos', 'injection', 'brute_force']),
                    threat_level=random.choice(list(ThreatLevel)),
                    title=f"Threat detected: {random.choice(['Suspicious activity', 'Malware detected', 'Attack attempt'])}",
                    description=f"Threat detected from {random.choice(['192.168.1.', '10.0.0.', '172.16.0.'])}{random.randint(1, 254)}",
                    source_ip=f"{random.choice(['192.168.1.', '10.0.0.', '172.16.0.'])}{random.randint(1, 254)}",
                    target_user=random.choice(['admin', 'user1', 'user2', None]),
                    timestamp=datetime.utcnow() - timedelta(seconds=random.randint(0, 3600)),
                    details={'severity': random.uniform(0.1, 1.0)},
                    is_resolved=random.choice([True, False])
                )
                threats.append(threat)
            
            widget.data = {
                'threats': [
                    {
                        'item_id': threat.item_id,
                        'threat_type': threat.threat_type,
                        'threat_level': threat.threat_level.value,
                        'title': threat.title,
                        'description': threat.description,
                        'source_ip': threat.source_ip,
                        'target_user': threat.target_user,
                        'timestamp': threat.timestamp.isoformat(),
                        'details': threat.details,
                        'is_resolved': threat.is_resolved
                    }
                    for threat in threats
                ],
                'total_count': len(threats),
                'active_count': len([t for t in threats if not t.is_resolved]),
                'last_update': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating threat feed: {e}")
    
    async def _update_system_health(self, widget: DashboardWidget):
        """Update system health widget"""
        try:
            # Simulate system health data
            services = [
                HealthCard(
                    card_id='api_service',
                    service_name='API Service',
                    status=random.choice(list(SystemStatus)),
                    health_score=random.uniform(0.7, 1.0),
                    metrics={
                        'cpu_usage': random.uniform(20, 80),
                        'memory_usage': random.uniform(30, 70),
                        'request_rate': random.uniform(100, 1000)
                    },
                    last_check=datetime.utcnow(),
                    alerts=[],
                    uptime=random.uniform(99.0, 100.0),
                    response_time=random.uniform(10, 100)
                ),
                HealthCard(
                    card_id='database_service',
                    service_name='Database',
                    status=random.choice(list(SystemStatus)),
                    health_score=random.uniform(0.8, 1.0),
                    metrics={
                        'cpu_usage': random.uniform(10, 60),
                        'memory_usage': random.uniform(40, 80),
                        'connections': random.randint(50, 200)
                    },
                    last_check=datetime.utcnow(),
                    alerts=[],
                    uptime=random.uniform(99.5, 100.0),
                    response_time=random.uniform(5, 50)
                ),
                HealthCard(
                    card_id='cache_service',
                    service_name='Cache',
                    status=random.choice(list(SystemStatus)),
                    health_score=random.uniform(0.9, 1.0),
                    metrics={
                        'hit_rate': random.uniform(0.8, 1.0),
                        'memory_usage': random.uniform(20, 60),
                        'eviction_rate': random.uniform(0.01, 0.1)
                    },
                    last_check=datetime.utcnow(),
                    alerts=[],
                    uptime=random.uniform(99.9, 100.0),
                    response_time=random.uniform(1, 10)
                ),
                HealthCard(
                    card_id='websocket_service',
                    service_name='WebSocket',
                    status=random.choice(list(SystemStatus)),
                    health_score=random.uniform(0.85, 1.0),
                    metrics={
                        'connections': random.randint(100, 500),
                        'message_rate': random.uniform(1000, 10000),
                        'latency': random.uniform(1, 50)
                    },
                    last_check=datetime.utcnow(),
                    alerts=[],
                    uptime=random.uniform(99.8, 100.0),
                    response_time=random.uniform(5, 25)
                )
            ]
            
            widget.data = {
                'services': [
                    {
                        'card_id': service.card_id,
                        'service_name': service.service_name,
                        'status': service.status.value,
                        'health_score': service.health_score,
                        'metrics': service.metrics,
                        'last_check': service.last_check.isoformat(),
                        'alerts': service.alerts,
                        'uptime': service.uptime,
                        'response_time': service.response_time
                    }
                    for service in services
                ],
                'overall_health': sum(service.health_score for service in services) / len(services),
                'last_update': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating system health: {e}")
    
    async def _update_performance_metrics(self, widget: DashboardWidget):
        """Update performance metrics widget"""
        try:
            # Simulate performance metrics
            widget.data = {
                'cpu_usage': random.uniform(20, 80),
                'memory_usage': random.uniform(30, 70),
                'disk_usage': random.uniform(10, 60),
                'network_io': random.uniform(1000, 10000),
                'request_rate': random.uniform(100, 1000),
                'response_time': random.uniform(10, 100),
                'error_rate': random.uniform(0.01, 0.05),
                'throughput': random.uniform(1000, 10000),
                'last_update': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating performance metrics: {e}")
    
    async def _update_security_metrics(self, widget: DashboardWidget):
        """Update security metrics widget"""
        try:
            # Simulate security metrics
            widget.data = {
                'blocked_requests': random.randint(1000, 10000),
                'failed_logins': random.randint(10, 100),
                'suspicious_ips': random.randint(50, 500),
                'malware_detected': random.randint(0, 10),
                'security_score': random.uniform(0.8, 1.0),
                'threat_level': random.choice(list(ThreatLevel)).value,
                'active_alerts': random.randint(0, 20),
                'resolved_alerts': random.randint(100, 1000),
                'last_update': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error updating security metrics: {e}")
    
    async def _broadcast_updates(self):
        """Broadcast updates to WebSocket clients"""
        try:
            # Prepare dashboard data
            dashboard_data = {
                'type': 'dashboard_update',
                'timestamp': datetime.utcnow().isoformat(),
                'widgets': {
                    widget_id: {
                        'widget_id': widget.widget_id,
                        'widget_type': widget.widget_type,
                        'title': widget.title,
                        'data': widget.data,
                        'last_refresh': widget.last_refresh.isoformat()
                    }
                    for widget_id, widget in self.widgets.items()
                }
            }
            
            # Broadcast to all connected clients
            message = json.dumps(dashboard_data)
            
            for connection_id, websocket in self.websocket_connections.items():
                try:
                    await websocket.send_text(message)
                except Exception as e:
                    logger.error(f"Error sending to WebSocket {connection_id}: {e}")
                    # Remove failed connection
                    del self.websocket_connections[connection_id]
            
        except Exception as e:
            logger.error(f"Error broadcasting updates: {e}")
    
    async def add_websocket_connection(self, connection_id: str, websocket):
        """Add WebSocket connection"""
        try:
            self.websocket_connections[connection_id] = websocket
            logger.info(f"WebSocket connection added: {connection_id}")
            
            # Send initial dashboard data
            await self._send_initial_data(connection_id)
            
        except Exception as e:
            logger.error(f"Error adding WebSocket connection: {e}")
    
    async def remove_websocket_connection(self, connection_id: str):
        """Remove WebSocket connection"""
        try:
            if connection_id in self.websocket_connections:
                del self.websocket_connections[connection_id]
                logger.info(f"WebSocket connection removed: {connection_id}")
            
        except Exception as e:
            logger.error(f"Error removing WebSocket connection: {e}")
    
    async def _send_initial_data(self, connection_id: str):
        """Send initial dashboard data to new connection"""
        try:
            if connection_id not in self.websocket_connections:
                return
            
            # Prepare initial data
            initial_data = {
                'type': 'initial_data',
                'timestamp': datetime.utcnow().isoformat(),
                'dashboard_config': self.dashboard_config,
                'widgets': {
                    widget_id: {
                        'widget_id': widget.widget_id,
                        'widget_type': widget.widget_type,
                        'title': widget.title,
                        'position': widget.position,
                        'size': widget.size,
                        'config': widget.config,
                        'data': widget.data,
                        'last_refresh': widget.last_refresh.isoformat()
                    }
                    for widget_id, widget in self.widgets.items()
                }
            }
            
            message = json.dumps(initial_data)
            await self.websocket_connections[connection_id].send_text(message)
            
        except Exception as e:
            logger.error(f"Error sending initial data: {e}")
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data"""
        try:
            return {
                'config': self.dashboard_config,
                'widgets': {
                    widget_id: {
                        'widget_id': widget.widget_id,
                        'widget_type': widget.widget_type,
                        'title': widget.title,
                        'position': widget.position,
                        'size': widget.size,
                        'config': widget.config,
                        'data': widget.data,
                        'last_refresh': widget.last_refresh.isoformat()
                    }
                    for widget_id, widget in self.widgets.items()
                },
                'connections': len(self.websocket_connections),
                'is_running': self.is_running,
                'last_update': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {'error': str(e)}


class AnimatedThreatFeed:
    """Animated threat feed system"""
    
    def __init__(self):
        """Initialize animated threat feed"""
        self.threat_items: deque = deque(maxlen=100)
        self.animation_speed: float = 1.0
        self.auto_scroll: bool = True
        self.filter_level: Optional[ThreatLevel] = None
        self.filter_type: Optional[str] = None
        
        logger.info("Animated threat feed initialized")
    
    async def add_threat(self, threat: ThreatFeedItem):
        """Add threat to feed"""
        try:
            self.threat_items.appendleft(threat)
            
            # Trigger animation
            await self._trigger_animation(threat)
            
            logger.info(f"Threat added to feed: {threat.item_id}")
            
        except Exception as e:
            logger.error(f"Error adding threat to feed: {e}")
    
    async def _trigger_animation(self, threat: ThreatFeedItem):
        """Trigger animation for new threat"""
        try:
            # In a real implementation, this would trigger CSS animations
            # For now, we'll just log the animation
            logger.debug(f"Animation triggered for threat: {threat.item_id}")
            
        except Exception as e:
            logger.error(f"Error triggering animation: {e}")
    
    async def get_feed_items(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get threat feed items"""
        try:
            items = list(self.threat_items)[:limit]
            
            # Apply filters
            if self.filter_level:
                items = [item for item in items if item.threat_level == self.filter_level]
            
            if self.filter_type:
                items = [item for item in items if item.threat_type == self.filter_type]
            
            return [
                {
                    'item_id': item.item_id,
                    'threat_type': item.threat_type,
                    'threat_level': item.threat_level.value,
                    'title': item.title,
                    'description': item.description,
                    'source_ip': item.source_ip,
                    'target_user': item.target_user,
                    'timestamp': item.timestamp.isoformat(),
                    'details': item.details,
                    'is_resolved': item.is_resolved,
                    'animation_class': self._get_animation_class(item)
                }
                for item in items
            ]
            
        except Exception as e:
            logger.error(f"Error getting feed items: {e}")
            return []
    
    def _get_animation_class(self, threat: ThreatFeedItem) -> str:
        """Get animation class for threat"""
        try:
            if threat.threat_level == ThreatLevel.CRITICAL:
                return "threat-critical"
            elif threat.threat_level == ThreatLevel.HIGH:
                return "threat-high"
            elif threat.threat_level == ThreatLevel.MEDIUM:
                return "threat-medium"
            else:
                return "threat-low"
                
        except Exception:
            return "threat-default"


class WebSocketLiveEvents:
    """WebSocket live events system"""
    
    def __init__(self):
        """Initialize WebSocket live events"""
        self.connections: Dict[str, Any] = {}
        self.event_queue = asyncio.Queue()
        self.broadcast_task: Optional[asyncio.Task] = None
        self.is_running: bool = False
        
        # Event configuration
        self.event_config = {
            'max_connections': 1000,
            'message_queue_size': 10000,
            'heartbeat_interval': 30,
            'reconnect_timeout': 5
        }
        
        logger.info("WebSocket live events initialized")
    
    async def start(self):
        """Start WebSocket live events"""
        try:
            logger.info("Starting WebSocket live events")
            
            # Start broadcast task
            self.broadcast_task = asyncio.create_task(self._broadcast_loop())
            
            self.is_running = True
            logger.info("WebSocket live events started")
            
        except Exception as e:
            logger.error(f"Error starting WebSocket live events: {e}")
            raise
    
    async def stop(self):
        """Stop WebSocket live events"""
        try:
            logger.info("Stopping WebSocket live events")
            
            self.is_running = False
            
            # Cancel broadcast task
            if self.broadcast_task:
                self.broadcast_task.cancel()
            
            # Close all connections
            for connection_id, websocket in self.connections.items():
                try:
                    await websocket.close()
                except:
                    pass
            
            self.connections.clear()
            
            logger.info("WebSocket live events stopped")
            
        except Exception as e:
            logger.error(f"Error stopping WebSocket live events: {e}")
    
    async def _broadcast_loop(self):
        """Broadcast loop for live events"""
        while self.is_running:
            try:
                # Get event from queue
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Broadcast to all connections
                await self._broadcast_event(event)
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in broadcast loop: {e}")
                await asyncio.sleep(1)
    
    async def add_connection(self, connection_id: str, websocket):
        """Add WebSocket connection"""
        try:
            if len(self.connections) >= self.event_config['max_connections']:
                await websocket.close(code=1013, reason="Maximum connections reached")
                return False
            
            self.connections[connection_id] = websocket
            
            # Send welcome message
            welcome_event = {
                'type': 'connection_established',
                'connection_id': connection_id,
                'timestamp': datetime.utcnow().isoformat(),
                'message': 'Connected to MARY V5 SHIELD CORE live events'
            }
            
            await websocket.send_text(json.dumps(welcome_event))
            
            logger.info(f"WebSocket connection added: {connection_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding connection: {e}")
            return False
    
    async def remove_connection(self, connection_id: str):
        """Remove WebSocket connection"""
        try:
            if connection_id in self.connections:
                del self.connections[connection_id]
                logger.info(f"WebSocket connection removed: {connection_id}")
            
        except Exception as e:
            logger.error(f"Error removing connection: {e}")
    
    async def _broadcast_event(self, event: Dict[str, Any]):
        """Broadcast event to all connections"""
        try:
            message = json.dumps(event)
            
            failed_connections = []
            
            for connection_id, websocket in self.connections.items():
                try:
                    await websocket.send_text(message)
                except Exception as e:
                    logger.error(f"Error sending to connection {connection_id}: {e}")
                    failed_connections.append(connection_id)
            
            # Remove failed connections
            for connection_id in failed_connections:
                await self.remove_connection(connection_id)
            
        except Exception as e:
            logger.error(f"Error broadcasting event: {e}")
    
    async def emit_event(self, event_type: str, data: Dict[str, Any]):
        """Emit live event"""
        try:
            event = {
                'type': event_type,
                'timestamp': datetime.utcnow().isoformat(),
                'data': data
            }
            
            await self.event_queue.put(event)
            
        except Exception as e:
            logger.error(f"Error emitting event: {e}")


class RoleBasedAccessControl:
    """Role-based access control system"""
    
    def __init__(self):
        """Initialize RBAC system"""
        self.user_roles: Dict[str, UserRole] = {}
        self.role_permissions: Dict[UserRole, List[str]] = {
            UserRole.ADMIN: [
                'dashboard.view', 'dashboard.edit', 'dashboard.delete',
                'threats.view', 'threats.manage', 'threats.resolve',
                'system.view', 'system.manage', 'system.restart',
                'users.view', 'users.manage', 'users.create', 'users.delete',
                'audit.view', 'audit.export',
                'config.view', 'config.edit'
            ],
            UserRole.OPERATOR: [
                'dashboard.view', 'dashboard.edit',
                'threats.view', 'threats.manage', 'threats.resolve',
                'system.view', 'system.manage',
                'audit.view'
            ],
            UserRole.ANALYST: [
                'dashboard.view',
                'threats.view', 'threats.resolve',
                'system.view',
                'audit.view', 'audit.export'
            ],
            UserRole.VIEWER: [
                'dashboard.view',
                'threats.view',
                'system.view'
            ],
            UserRole.SECURITY_OFFICER: [
                'dashboard.view', 'dashboard.edit',
                'threats.view', 'threats.manage', 'threats.resolve',
                'system.view', 'system.manage',
                'audit.view', 'audit.export',
                'security.view', 'security.manage'
            ],
            UserRole.COMPLIANCE_OFFICER: [
                'dashboard.view',
                'threats.view',
                'system.view',
                'audit.view', 'audit.export',
                'compliance.view', 'compliance.export'
            ]
        }
        
        logger.info("Role-based access control initialized")
    
    async def assign_role(self, user_id: str, role: UserRole):
        """Assign role to user"""
        try:
            self.user_roles[user_id] = role
            logger.info(f"Role assigned: {user_id} -> {role.value}")
            
        except Exception as e:
            logger.error(f"Error assigning role: {e}")
    
    async def check_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has permission"""
        try:
            user_role = self.user_roles.get(user_id)
            if not user_role:
                return False
            
            permissions = self.role_permissions.get(user_role, [])
            return permission in permissions
            
        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False
    
    async def get_user_permissions(self, user_id: str) -> List[str]:
        """Get user permissions"""
        try:
            user_role = self.user_roles.get(user_id)
            if not user_role:
                return []
            
            return self.role_permissions.get(user_role, [])
            
        except Exception as e:
            logger.error(f"Error getting user permissions: {e}")
            return []


class DarkCyberTheme:
    """Dark cyber theme system"""
    
    def __init__(self):
        """Initialize dark cyber theme"""
        self.theme_config = {
            'primary_color': '#00ff88',
            'secondary_color': '#ff0088',
            'accent_color': '#0088ff',
            'warning_color': '#ffaa00',
            'danger_color': '#ff4444',
            'success_color': '#00ff44',
            'background_color': '#0a0a0a',
            'surface_color': '#1a1a1a',
            'text_color': '#ffffff',
            'text_secondary': '#888888',
            'border_color': '#333333',
            'grid_color': '#2a2a2a'
        }
        
        self.animation_config = {
            'enabled': True,
            'speed': 'normal',
            'effects': ['glow', 'pulse', 'slide'],
            'transitions': True
        }
        
        logger.info("Dark cyber theme initialized")
    
    def get_theme_css(self) -> str:
        """Get theme CSS"""
        try:
            return f"""
            :root {{
                --primary-color: {self.theme_config['primary_color']};
                --secondary-color: {self.theme_config['secondary_color']};
                --accent-color: {self.theme_config['accent_color']};
                --warning-color: {self.theme_config['warning_color']};
                --danger-color: {self.theme_config['danger_color']};
                --success-color: {self.theme_config['success_color']};
                --background-color: {self.theme_config['background_color']};
                --surface-color: {self.theme_config['surface_color']};
                --text-color: {self.theme_config['text_color']};
                --text-secondary: {self.theme_config['text_secondary']};
                --border-color: {self.theme_config['border_color']};
                --grid-color: {self.theme_config['grid_color']};
            }}
            
            body {{
                background-color: var(--background-color);
                color: var(--text-color);
                font-family: 'Courier New', monospace;
                margin: 0;
                padding: 0;
            }}
            
            .dashboard {{
                background: linear-gradient(135deg, var(--background-color) 0%, var(--surface-color) 100%);
                min-height: 100vh;
                display: grid;
                grid-template-columns: repeat(12, 1fr);
                grid-template-rows: auto 1fr auto;
                gap: 20px;
                padding: 20px;
            }}
            
            .widget {{
                background: var(--surface-color);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 20px;
                box-shadow: 0 4px 20px rgba(0, 255, 136, 0.1);
                position: relative;
                overflow: hidden;
            }}
            
            .widget::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: linear-gradient(90deg, var(--primary-color), var(--accent-color), var(--secondary-color));
                animation: glow 3s ease-in-out infinite;
            }}
            
            .widget-title {{
                color: var(--primary-color);
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 15px;
                text-transform: uppercase;
                letter-spacing: 2px;
            }}
            
            .threat-feed {{
                max-height: 400px;
                overflow-y: auto;
            }}
            
            .threat-item {{
                border-left: 3px solid var(--border-color);
                padding: 10px;
                margin-bottom: 10px;
                background: rgba(26, 26, 26, 0.5);
                border-radius: 4px;
                transition: all 0.3s ease;
            }}
            
            .threat-item:hover {{
                border-left-color: var(--primary-color);
                background: rgba(26, 26, 26, 0.8);
                transform: translateX(5px);
            }}
            
            .threat-critical {{
                border-left-color: var(--danger-color) !important;
                animation: pulse 1s ease-in-out infinite;
            }}
            
            .threat-high {{
                border-left-color: var(--warning-color) !important;
            }}
            
            .threat-medium {{
                border-left-color: var(--accent-color) !important;
            }}
            
            .threat-low {{
                border-left-color: var(--success-color) !important;
            }}
            
            .health-card {{
                background: var(--surface-color);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 15px;
                position: relative;
            }}
            
            .health-status {{
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 10px;
            }}
            
            .health-healthy {{
                background: var(--success-color);
                box-shadow: 0 0 10px var(--success-color);
            }}
            
            .health-warning {{
                background: var(--warning-color);
                box-shadow: 0 0 10px var(--warning-color);
            }}
            
            .health-critical {{
                background: var(--danger-color);
                box-shadow: 0 0 10px var(--danger-color);
                animation: pulse 1s ease-in-out infinite;
            }}
            
            .metric-value {{
                font-size: 24px;
                font-weight: bold;
                color: var(--primary-color);
                margin: 10px 0;
            }}
            
            .metric-label {{
                color: var(--text-secondary);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            
            @keyframes glow {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.5; }}
            }}
            
            @keyframes pulse {{
                0%, 100% {{ transform: scale(1); opacity: 1; }}
                50% {{ transform: scale(1.1); opacity: 0.8; }}
            }}
            
            @keyframes slide {{
                from {{ transform: translateX(-100%); opacity: 0; }}
                to {{ transform: translateX(0); opacity: 1; }}
            }}
            
            .animate-slide {{
                animation: slide 0.5s ease-out;
            }}
            
            /* Responsive design */
            @media (max-width: 1200px) {{
                .dashboard {{
                    grid-template-columns: repeat(8, 1fr);
                }}
            }}
            
            @media (max-width: 768px) {{
                .dashboard {{
                    grid-template-columns: 1fr;
                    padding: 10px;
                    gap: 10px;
                }}
                
                .widget {{
                    padding: 15px;
                }}
            }}
            """
            
        except Exception as e:
            logger.error(f"Error generating theme CSS: {e}")
            return ""


class OperatorConsole:
    """Operator console with advanced controls"""
    
    def __init__(self):
        """Initialize operator console"""
        self.console_commands: Dict[str, Callable] = {}
        self.command_history: List[Dict[str, Any]] = []
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.system_controls: Dict[str, Any] = {}
        
        # Initialize default commands
        self._initialize_commands()
        
        logger.info("Operator console initialized")
    
    def _initialize_commands(self):
        """Initialize console commands"""
        try:
            self.console_commands = {
                'status': self._cmd_status,
                'restart': self._cmd_restart,
                'block': self._cmd_block,
                'investigate': self._cmd_investigate,
                'resolve': self._cmd_resolve,
                'escalate': self._cmd_escalate,
                'scan': self._cmd_scan,
                'monitor': self._cmd_monitor
            }
            
        except Exception as e:
            logger.error(f"Error initializing commands: {e}")
    
    async def execute_command(self, command: str, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Execute console command"""
        try:
            # Check user permissions
            from .rbac import rbac_system
            
            if not await rbac_system.check_permission(user_id, 'console.execute'):
                return {'error': 'Permission denied'}
            
            # Execute command
            if command in self.console_commands:
                result = await self.console_commands[command](params, user_id)
                
                # Add to history
                self.command_history.append({
                    'command': command,
                    'params': params,
                    'user_id': user_id,
                    'timestamp': datetime.utcnow(),
                    'result': result
                })
                
                return result
            else:
                return {'error': f'Unknown command: {command}'}
                
        except Exception as e:
            logger.error(f"Error executing command {command}: {e}")
            return {'error': str(e)}
    
    async def _cmd_status(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Status command"""
        try:
            return {
                'system_status': 'operational',
                'active_threats': 23,
                'system_load': 45.2,
                'uptime': '99.97%',
                'last_update': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in status command: {e}")
            return {'error': str(e)}
    
    async def _cmd_restart(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Restart command"""
        try:
            service = params.get('service')
            
            # In a real implementation, this would restart the service
            return {
                'command': 'restart',
                'service': service,
                'status': 'restarting',
                'estimated_time': '30 seconds',
                'initiated_by': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in restart command: {e}")
            return {'error': str(e)}
    
    async def _cmd_block(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Block command"""
        try:
            ip_address = params.get('ip_address')
            
            # In a real implementation, this would block the IP
            return {
                'command': 'block',
                'ip_address': ip_address,
                'status': 'blocked',
                'duration': '24 hours',
                'initiated_by': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in block command: {e}")
            return {'error': str(e)}
    
    async def _cmd_investigate(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Investigate command"""
        try:
            threat_id = params.get('threat_id')
            
            # In a real implementation, this would start investigation
            return {
                'command': 'investigate',
                'threat_id': threat_id,
                'status': 'investigating',
                'assigned_to': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in investigate command: {e}")
            return {'error': str(e)}
    
    async def _cmd_resolve(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Resolve command"""
        try:
            threat_id = params.get('threat_id')
            resolution = params.get('resolution')
            
            # In a real implementation, this would resolve the threat
            return {
                'command': 'resolve',
                'threat_id': threat_id,
                'resolution': resolution,
                'resolved_by': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in resolve command: {e}")
            return {'error': str(e)}
    
    async def _cmd_escalate(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Escalate command"""
        try:
            threat_id = params.get('threat_id')
            level = params.get('level', 'high')
            
            # In a real implementation, this would escalate the threat
            return {
                'command': 'escalate',
                'threat_id': threat_id,
                'level': level,
                'escalated_by': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in escalate command: {e}")
            return {'error': str(e)}
    
    async def _cmd_scan(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Scan command"""
        try:
            target = params.get('target', 'system')
            
            # In a real implementation, this would start a scan
            return {
                'command': 'scan',
                'target': target,
                'status': 'scanning',
                'initiated_by': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in scan command: {e}")
            return {'error': str(e)}
    
    async def _cmd_monitor(self, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Monitor command"""
        try:
            target = params.get('target')
            
            # In a real implementation, this would start monitoring
            return {
                'command': 'monitor',
                'target': target,
                'status': 'monitoring',
                'initiated_by': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in monitor command: {e}")
            return {'error': str(e)}


class EnterpriseUILayer:
    """Main enterprise UI layer coordinator"""
    
    def __init__(self):
        """Initialize enterprise UI layer"""
        self.dashboard = RealTimeDashboard()
        self.threat_feed = AnimatedThreatFeed()
        self.websocket_events = WebSocketLiveEvents()
        self.rbac = RoleBasedAccessControl()
        self.theme = DarkCyberTheme()
        self.console = OperatorConsole()
        
        self.is_running: bool = False
        self.ui_config: Dict[str, Any] = {}
        
        logger.info("Enterprise UI layer initialized")
    
    async def start(self):
        """Start enterprise UI layer"""
        try:
            logger.info("Starting enterprise UI layer")
            
            # Start components
            await self.dashboard.start()
            await self.websocket_events.start()
            
            self.is_running = True
            logger.info("Enterprise UI layer started successfully")
            
        except Exception as e:
            logger.error(f"Error starting enterprise UI layer: {e}")
            raise
    
    async def stop(self):
        """Stop enterprise UI layer"""
        try:
            logger.info("Stopping enterprise UI layer")
            
            self.is_running = False
            
            # Stop components
            await self.dashboard.stop()
            await self.websocket_events.stop()
            
            logger.info("Enterprise UI layer stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping enterprise UI layer: {e}")
    
    async def get_dashboard_html(self) -> str:
        """Get dashboard HTML"""
        try:
            theme_css = self.theme.get_theme_css()
            
            return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MARY V5 SHIELD CORE - Enterprise Dashboard</title>
    <style>{theme_css}</style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
</head>
<body>
    <div class="dashboard">
        <header style="grid-column: 1 / -1;">
            <h1 style="color: var(--primary-color); text-align: center; font-size: 2.5em; margin: 20px 0;">
                MARY V5 SHIELD CORE
            </h1>
            <p style="text-align: center; color: var(--text-secondary); margin-bottom: 20px;">
                Enterprise Security Operations Center
            </p>
        </header>
        
        <!-- System Overview -->
        <section class="widget" style="grid-column: 1 / -1;">
            <h2 class="widget-title">System Overview</h2>
            <div id="system-overview">
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                    <div>
                        <div class="metric-value" id="total-threats">0</div>
                        <div class="metric-label">Total Threats</div>
                    </div>
                    <div>
                        <div class="metric-value" id="active-threats">0</div>
                        <div class="metric-label">Active Threats</div>
                    </div>
                    <div>
                        <div class="metric-value" id="system-status">HEALTHY</div>
                        <div class="metric-label">System Status</div>
                    </div>
                    <div>
                        <div class="metric-value" id="uptime">99.9%</div>
                        <div class="metric-label">Uptime</div>
                    </div>
                </div>
            </div>
        </section>
        
        <!-- Threat Feed -->
        <section class="widget" style="grid-column: span 8;">
            <h2 class="widget-title">Live Threat Feed</h2>
            <div class="threat-feed" id="threat-feed">
                <!-- Threat items will be populated here -->
            </div>
        </section>
        
        <!-- System Health -->
        <section class="widget" style="grid-column: span 4;">
            <h2 class="widget-title">System Health</h2>
            <div id="system-health">
                <!-- Health cards will be populated here -->
            </div>
        </section>
        
        <!-- Performance Metrics -->
        <section class="widget" style="grid-column: span 6;">
            <h2 class="widget-title">Performance Metrics</h2>
            <div style="height: 200px;">
                <canvas id="performance-chart"></canvas>
            </div>
        </section>
        
        <!-- Security Metrics -->
        <section class="widget" style="grid-column: span 6;">
            <h2 class="widget-title">Security Metrics</h2>
            <div style="height: 200px;">
                <canvas id="security-chart"></canvas>
            </div>
        </section>
        
        <!-- Operator Console -->
        <section class="widget" style="grid-column: 1 / -1;">
            <h2 class="widget-title">Operator Console</h2>
            <div>
                <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                    <input type="text" id="command-input" placeholder="Enter command..." style="flex: 1; background: var(--surface-color); color: var(--text-color); border: 1px solid var(--border-color); padding: 10px; border-radius: 4px;">
                    <button onclick="executeCommand()" style="background: var(--primary-color); color: var(--background-color); border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">Execute</button>
                </div>
                <div id="console-output" style="background: var(--background-color); border: 1px solid var(--border-color); border-radius: 4px; padding: 10px; height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px;"></div>
            </div>
        </section>
    </div>
    
    <script>
        // WebSocket connection
        const ws = new WebSocket('ws://localhost:8080/ws');
        
        // Chart configurations
        const performanceChart = new Chart(document.getElementById('performance-chart'), {{
            type: 'line',
            data: {{
                labels: [],
                datasets: [{{
                    label: 'CPU Usage',
                    data: [],
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    tension: 0.4
                }}, {{
                    label: 'Memory Usage',
                    data: [],
                    borderColor: '#ff0088',
                    backgroundColor: 'rgba(255, 0, 136, 0.1)',
                    tension: 0.4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{ color: '#888' }},
                        grid: {{ color: '#333' }}
                    }},
                    x: {{
                        ticks: {{ color: '#888' }},
                        grid: {{ color: '#333' }}
                    }}
                }},
                plugins: {{
                    legend: {{
                        labels: {{ color: '#fff' }}
                    }}
                }}
            }}
        }});
        
        const securityChart = new Chart(document.getElementById('security-chart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Blocked Requests', 'Failed Logins', 'Suspicious IPs', 'Resolved Alerts'],
                datasets: [{{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#00ff88', '#ff0088', '#0088ff', '#ffaa00']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        labels: {{ color: '#fff' }}
                    }}
                }}
            }}
        }});
        
        // WebSocket message handler
        ws.onmessage = function(event) {{
            const data = JSON.parse(event.data);
            
            if (data.type === 'dashboard_update') {{
                updateDashboard(data.widgets);
            }}
        }};
        
        function updateDashboard(widgets) {{
            // Update system overview
            if (widgets.system_overview) {{
                document.getElementById('total-threats').textContent = widgets.system_overview.data.total_threats;
                document.getElementById('active-threats').textContent = widgets.system_overview.data.active_threats;
                document.getElementById('system-status').textContent = widgets.system_overview.data.system_status.toUpperCase();
                document.getElementById('uptime').textContent = widgets.system_overview.data.uptime + '%';
            }}
            
            // Update threat feed
            if (widgets.threat_feed) {{
                const threatFeed = document.getElementById('threat-feed');
                threatFeed.innerHTML = '';
                
                widgets.threat_feed.data.threats.forEach(threat => {{
                    const threatItem = document.createElement('div');
                    threatItem.className = `threat-item threat-${{threat.threat_level}`;
                    threatItem.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-weight: bold;">${{threat.title}}</span>
                            <span style="color: var(--text-secondary); font-size: 12px;">${{new Date(threat.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div style="color: var(--text-secondary); font-size: 14px; margin-top: 5px;">${{threat.description}}</div>
                        <div style="display: flex; gap: 10px; margin-top: 5px;">
                            <span style="color: var(--text-secondary); font-size: 12px;">IP: ${{threat.source_ip}}</span>
                            ${{threat.target_user ? `<span style="color: var(--text-secondary); font-size: 12px;">User: ${{threat.target_user}</span>` : ''}}
                        </div>
                    `;
                    threatItem.classList.add('animate-slide');
                    threatFeed.appendChild(threatItem);
                }});
            }}
            
            // Update system health
            if (widgets.system_health) {{
                const systemHealth = document.getElementById('system-health');
                systemHealth.innerHTML = '';
                
                widgets.system_health.data.services.forEach(service => {{
                    const healthCard = document.createElement('div');
                    healthCard.className = 'health-card';
                    healthCard.innerHTML = `
                        <div style="display: flex; align-items: center;">
                            <div class="health-status health-${{service.status}}"></div>
                            <div>
                                <div style="font-weight: bold;">${{service.service_name}}</div>
                                <div style="color: var(--text-secondary); font-size: 12px;">Health: ${(service.health_score * 100).toFixed(1)}%</div>
                            </div>
                        </div>
                        <div style="margin-top: 10px;">
                            <div style="font-size: 12px; color: var(--text-secondary);">CPU: ${{service.metrics.cpu_usage.toFixed(1)}%</div>
                            <div style="font-size: 12px; color: var(--text-secondary);">Memory: ${{service.metrics.memory_usage.toFixed(1)}%</div>
                        </div>
                    `;
                    systemHealth.appendChild(healthCard);
                }});
            }}
            
            // Update performance metrics
            if (widgets.performance_metrics) {{
                const perfData = widgets.performance_metrics.data;
                
                if (performanceChart.data.labels.length > 50) {{
                    performanceChart.data.labels.shift();
                    performanceChart.data.datasets[0].data.shift();
                    performanceChart.data.datasets[1].data.shift();
                }}
                
                performanceChart.data.labels.push(new Date().toLocaleTimeString());
                performanceChart.data.datasets[0].data.push(perfData.cpu_usage);
                performanceChart.data.datasets[1].data.push(perfData.memory_usage);
                performanceChart.update();
            }}
            
            // Update security metrics
            if (widgets.security_metrics) {{
                const secData = widgets.security_metrics.data;
                
                securityChart.data.datasets[0].data = [
                    secData.blocked_requests,
                    secData.failed_logins,
                    secData.suspicious_ips,
                    secData.resolved_alerts
                ];
                securityChart.update();
            }}
        }}
        
        // Command execution
        async function executeCommand() {{
            const input = document.getElementById('command-input');
            const output = document.getElementById('console-output');
            
            const command = input.value.trim();
            if (!command) return;
            
            try {{
                const response = await fetch('/api/console/execute', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{
                        command: command,
                        user_id: 'demo_user'
                    }})
                }});
                
                const result = await response.json();
                
                output.innerHTML += `<div style="color: var(--primary-color);">${{new Date().toLocaleTimeString()}: ${command}</div>`;
                output.innerHTML += `<div style="color: ${result.error ? 'var(--danger-color)' : 'var(--success-color)'};">${JSON.stringify(result, null, 2)}</div>`;
                output.innerHTML += `<div style="color: var(--text-secondary);">--- ---</div>`;
                output.scrollTop = output.scrollHeight;
                
                input.value = '';
                
            }} catch (error) {{
                output.innerHTML += `<div style="color: var(--danger-color);">${{new Date().toLocaleTimeString()}: ERROR - ${error.message}}</div>`;
                output.scrollTop = output.scrollHeight;
            }}
        }}
        
        // Initialize dashboard
        async function initializeDashboard() {{
            try {{
                const response = await fetch('/api/dashboard');
                const data = await response.json();
                updateDashboard(data.widgets);
            }} catch (error) {{
                console.error('Error initializing dashboard:', error);
            }}
        }}
        
        // Initialize on load
        document.addEventListener('DOMContentLoaded', initializeDashboard);
    </script>
</body>
</html>
            """
            
        except Exception as e:
            logger.error(f"Error generating dashboard HTML: {e}")
            return "<html><body><h1>Error loading dashboard</h1></body></html>"
    
    async def get_ui_status(self) -> Dict[str, Any]:
        """Get UI layer status"""
        try:
            return {
                'is_running': self.is_running,
                'dashboard': {
                    'widgets_count': len(self.dashboard.widgets),
                    'connections_count': len(self.dashboard.websocket_connections),
                    'is_running': self.dashboard.is_running
                },
                'threat_feed': {
                    'items_count': len(self.threat_feed.threat_items),
                    'animation_speed': self.threat_feed.animation_speed,
                    'auto_scroll': self.threat_feed.auto_scroll
                },
                'websocket_events': {
                    'connections_count': len(self.websocket_events.connections),
                    'is_running': self.websocket_events.is_running,
                    'queue_size': self.websocket_events.event_queue.qsize()
                },
                'theme': {
                    'config': self.theme.theme_config,
                    'animation_config': self.theme.animation_config
                },
                'console': {
                    'commands_count': len(self.console.console_commands),
                    'history_count': len(self.console.command_history),
                    'active_sessions': len(self.console.active_sessions)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting UI status: {e}")
            return {'error': str(e)}


# Global enterprise UI layer instance
enterprise_ui_layer = EnterpriseUILayer()


# API functions
async def initialize_enterprise_ui() -> str:
    """Initialize enterprise UI layer"""
    try:
        await enterprise_ui_layer.start()
        logger.info("Enterprise UI layer initialized")
        return "Enterprise UI layer initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing enterprise UI layer: {e}")
        return f"Error initializing enterprise UI layer: {e}"


async def stop_enterprise_ui() -> str:
    """Stop enterprise UI layer"""
    try:
        await enterprise_ui_layer.stop()
        logger.info("Enterprise UI layer stopped")
        return "Enterprise UI layer stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping enterprise UI layer: {e}")
        return f"Error stopping enterprise UI layer: {e}"


async def get_enterprise_dashboard() -> str:
    """Get enterprise dashboard HTML"""
    try:
        return await enterprise_ui_layer.get_dashboard_html()
    except Exception as e:
        logger.error(f"Error getting enterprise dashboard: {e}")
        return "<html><body><h1>Error loading dashboard</h1></body></html>"


async def get_ui_status() -> Dict[str, Any]:
    """Get UI layer status"""
    try:
        return await enterprise_ui_layer.get_ui_status()
    except Exception as e:
        logger.error(f"Error getting UI status: {e}")
        return {'error': str(e)}


async def execute_console_command(command: str, params: Dict[str, Any], user_id: str) -> Dict[str, Any]:
    """Execute console command"""
    try:
        return await enterprise_ui_layer.console.execute_command(command, params, user_id)
    except Exception as e:
        logger.error(f"Error executing console command: {e}")
        return {'error': str(e)}


# Initialize enterprise UI layer
async def initialize_ui_system() -> str:
    """Initialize UI system"""
    try:
        await initialize_enterprise_ui()
        logger.info("UI system initialized")
        return "UI system initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing UI system: {e}")
        return f"Error initializing UI system: {e}"


# Cleanup function
async def cleanup_ui_system() -> str:
    """Cleanup UI system"""
    try:
        await stop_enterprise_ui()
        logger.info("UI system cleaned up")
        return "UI system cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up UI system: {e}")
        return f"Error cleaning up UI system: {e}"
