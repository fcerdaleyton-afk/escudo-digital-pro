#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - SOC Dashboard Mode
Real-time security operations center dashboard with Grafana compatibility
"""

import os
import sys
import asyncio
import logging
import json
import time
import math
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
        logging.FileHandler('/app/logs/soc_dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """Threat severity enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status enumeration"""
    ACTIVE = "active"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    INVESTIGATING = "investigating"


class DataSourceType(Enum):
    """Data source type enumeration"""
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"
    WEBSOCKET = "websocket"
    INTERNAL = "internal"


@dataclass
class ThreatEvent:
    """Threat event data structure"""
    event_id: str
    threat_type: str
    severity: ThreatSeverity
    status: AlertStatus
    timestamp: datetime
    source_ip: str
    target_user: Optional[str]
    description: str
    details: Dict[str, Any]
    confidence: float
    blocked: bool
    resolved_at: Optional[datetime]
    assigned_to: Optional[str]
    tags: List[str]
    metadata: Dict[str, Any]


@dataclass
class AuthAbuseEvent:
    """Authentication abuse event"""
    event_id: str
    user_id: str
    ip_address: str
    user_agent: str
    location: Dict[str, Any]
    timestamp: datetime
    abuse_type: str
    severity: ThreatSeverity
    attempts: int
    blocked: bool
    details: Dict[str, Any]


@dataclass
class SuspiciousIP:
    """Suspicious IP data structure"""
    ip_address: str
    reputation_score: float
    threat_level: ThreatSeverity
    first_seen: datetime
    last_seen: datetime
    total_requests: int
    blocked_requests: int
    countries: List[str]
    attack_types: List[str]
    metadata: Dict[str, Any]


@dataclass
class WebSocketAlert:
    """WebSocket alert data structure"""
    alert_id: str
    connection_id: str
    client_ip: str
    alert_type: str
    severity: ThreatSeverity
    timestamp: datetime
    description: str
    details: Dict[str, Any]
    resolved: bool


@dataclass
class BlockedRequest:
    """Blocked request data structure"""
    request_id: str
    timestamp: datetime
    ip_address: str
    endpoint: str
    method: str
    user_agent: str
    block_reason: str
    severity: ThreatSeverity
    details: Dict[str, Any]


@dataclass
class SystemLoadMetric:
    """System load metric data structure"""
    metric_name: str
    value: float
    unit: str
    timestamp: datetime
    threshold: float
    status: str
    details: Dict[str, Any]


class SOCDashboardDataCollector:
    """SOC dashboard data collector"""
    
    def __init__(self):
        """Initialize SOC dashboard data collector"""
        self.threat_events: deque = deque(maxlen=10000)
        self.auth_abuse_events: deque = deque(maxlen=5000)
        self.suspicious_ips: Dict[str, SuspiciousIP] = {}
        self.websocket_alerts: deque = deque(maxlen=5000)
        self.blocked_requests: deque = deque(maxlen=10000)
        self.system_metrics: deque = deque(maxlen=1000)
        
        # Data sources
        self.data_sources: Dict[DataSourceType, Any] = {}
        
        # WebSocket connections
        self.websocket_connections: Dict[str, Any] = {}
        
        # Collection configuration
        self.config = {
            'collection_interval': 5,  # seconds
            'retention_period': 86400,  # 24 hours
            'max_events_per_type': 10000,
            'real_time_updates': True,
            'enable_grafana_export': True
        }
        
        # Statistics
        self.stats = {
            'total_threats': 0,
            'total_auth_abuse': 0,
            'total_suspicious_ips': 0,
            'total_websocket_alerts': 0,
            'total_blocked_requests': 0,
            'last_update': datetime.utcnow()
        }
        
        logger.info("SOC dashboard data collector initialized")
    
    async def start_collection(self):
        """Start data collection"""
        logger.info("Starting SOC dashboard data collection")
        
        # Start collection loop
        asyncio.create_task(self._collection_loop())
        
        logger.info("SOC dashboard data collection started")
    
    async def _collection_loop(self):
        """Main collection loop"""
        while True:
            try:
                # Collect data from various sources
                await self._collect_system_metrics()
                await self._cleanup_old_data()
                await self._update_statistics()
                
                # Wait for next collection
                await asyncio.sleep(self.config['collection_interval'])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                await asyncio.sleep(10)
    
    async def add_threat_event(self, event: ThreatEvent):
        """Add threat event"""
        try:
            self.threat_events.append(event)
            self.stats['total_threats'] += 1
            
            # Broadcast to WebSocket connections
            await self._broadcast_to_websockets('threat_event', {
                'event_id': event.event_id,
                'threat_type': event.threat_type,
                'severity': event.severity.value,
                'status': event.status.value,
                'timestamp': event.timestamp.isoformat(),
                'source_ip': event.source_ip,
                'target_user': event.target_user,
                'description': event.description,
                'confidence': event.confidence,
                'blocked': event.blocked
            })
            
            logger.info(f"Threat event added: {event.event_id}")
            
        except Exception as e:
            logger.error(f"Error adding threat event: {e}")
    
    async def add_auth_abuse_event(self, event: AuthAbuseEvent):
        """Add authentication abuse event"""
        try:
            self.auth_abuse_events.append(event)
            self.stats['total_auth_abuse'] += 1
            
            # Broadcast to WebSocket connections
            await self._broadcast_to_websockets('auth_abuse', {
                'event_id': event.event_id,
                'user_id': event.user_id,
                'ip_address': event.ip_address,
                'abuse_type': event.abuse_type,
                'severity': event.severity.value,
                'attempts': event.attempts,
                'blocked': event.blocked,
                'timestamp': event.timestamp.isoformat()
            })
            
            logger.info(f"Auth abuse event added: {event.event_id}")
            
        except Exception as e:
            logger.error(f"Error adding auth abuse event: {e}")
    
    async def add_suspicious_ip(self, ip_data: Dict[str, Any]):
        """Add or update suspicious IP"""
        try:
            ip_address = ip_data['ip_address']
            
            if ip_address not in self.suspicious_ips:
                self.suspicious_ips[ip_address] = SuspiciousIP(
                    ip_address=ip_address,
                    reputation_score=ip_data.get('reputation_score', 0.5),
                    threat_level=ThreatSeverity(ip_data.get('threat_level', 'medium')),
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    total_requests=0,
                    blocked_requests=0,
                    countries=[],
                    attack_types=[],
                    metadata=ip_data.get('metadata', {})
                )
                self.stats['total_suspicious_ips'] += 1
            else:
                # Update existing IP
                ip = self.suspicious_ips[ip_address]
                ip.last_seen = datetime.utcnow()
                ip.total_requests += ip_data.get('requests', 0)
                ip.blocked_requests += ip_data.get('blocked_requests', 0)
                
                if ip_data.get('country'):
                    if ip_data['country'] not in ip.countries:
                        ip.countries.append(ip_data['country'])
                
                if ip_data.get('attack_type'):
                    if ip_data['attack_type'] not in ip.attack_types:
                        ip.attack_types.append(ip_data['attack_type'])
            
            # Broadcast to WebSocket connections
            ip = self.suspicious_ips[ip_address]
            await self._broadcast_to_websockets('suspicious_ip', {
                'ip_address': ip.ip_address,
                'reputation_score': ip.reputation_score,
                'threat_level': ip.threat_level.value,
                'total_requests': ip.total_requests,
                'blocked_requests': ip.blocked_requests,
                'countries': ip.countries,
                'attack_types': ip.attack_types,
                'last_seen': ip.last_seen.isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error adding suspicious IP: {e}")
    
    async def add_websocket_alert(self, alert: WebSocketAlert):
        """Add WebSocket alert"""
        try:
            self.websocket_alerts.append(alert)
            self.stats['total_websocket_alerts'] += 1
            
            # Broadcast to WebSocket connections
            await self._broadcast_to_websockets('websocket_alert', {
                'alert_id': alert.alert_id,
                'connection_id': alert.connection_id,
                'client_ip': alert.client_ip,
                'alert_type': alert.alert_type,
                'severity': alert.severity.value,
                'description': alert.description,
                'resolved': alert.resolved,
                'timestamp': alert.timestamp.isoformat()
            })
            
            logger.info(f"WebSocket alert added: {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error adding WebSocket alert: {e}")
    
    async def add_blocked_request(self, request: BlockedRequest):
        """Add blocked request"""
        try:
            self.blocked_requests.append(request)
            self.stats['total_blocked_requests'] += 1
            
            # Broadcast to WebSocket connections
            await self._broadcast_to_websockets('blocked_request', {
                'request_id': request.request_id,
                'ip_address': request.ip_address,
                'endpoint': request.endpoint,
                'method': request.method,
                'block_reason': request.block_reason,
                'severity': request.severity.value,
                'timestamp': request.timestamp.isoformat()
            })
            
            logger.info(f"Blocked request added: {request.request_id}")
            
        except Exception as e:
            logger.error(f"Error adding blocked request: {e}")
    
    async def add_system_metric(self, metric: SystemLoadMetric):
        """Add system metric"""
        try:
            self.system_metrics.append(metric)
            
            # Broadcast to WebSocket connections
            await self._broadcast_to_websockets('system_metric', {
                'metric_name': metric.metric_name,
                'value': metric.value,
                'unit': metric.unit,
                'threshold': metric.threshold,
                'status': metric.status,
                'timestamp': metric.timestamp.isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error adding system metric: {e}")
    
    async def _collect_system_metrics(self):
        """Collect system metrics"""
        try:
            import psutil
            
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            await self.add_system_metric(SystemLoadMetric(
                metric_name="cpu_usage",
                value=cpu_percent,
                unit="percent",
                timestamp=datetime.utcnow(),
                threshold=80.0,
                status="normal" if cpu_percent < 80 else "critical",
                details={}
            ))
            
            # Memory metrics
            memory = psutil.virtual_memory()
            await self.add_system_metric(SystemLoadMetric(
                metric_name="memory_usage",
                value=memory.percent,
                unit="percent",
                timestamp=datetime.utcnow(),
                threshold=85.0,
                status="normal" if memory.percent < 85 else "critical",
                details={}
            ))
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            await self.add_system_metric(SystemLoadMetric(
                metric_name="disk_usage",
                value=disk.percent,
                unit="percent",
                timestamp=datetime.utcnow(),
                threshold=90.0,
                status="normal" if disk.percent < 90 else "critical",
                details={}
            ))
            
            # Network metrics
            network = psutil.net_io_counters()
            await self.add_system_metric(SystemLoadMetric(
                metric_name="network_io",
                value=network.bytes_sent + network.bytes_recv,
                unit="bytes",
                timestamp=datetime.utcnow(),
                threshold=1000000000,  # 1GB
                status="normal",
                details={}
            ))
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old data"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(seconds=self.config['retention_period'])
            
            # Clean up old threat events
            self.threat_events = deque(
                [event for event in self.threat_events if event.timestamp > cutoff_time],
                maxlen=self.config['max_events_per_type']
            )
            
            # Clean up old auth abuse events
            self.auth_abuse_events = deque(
                [event for event in self.auth_abuse_events if event.timestamp > cutoff_time],
                maxlen=self.config['max_events_per_type']
            )
            
            # Clean up old websocket alerts
            self.websocket_alerts = deque(
                [alert for alert in self.websocket_alerts if alert.timestamp > cutoff_time],
                maxlen=self.config['max_events_per_type']
            )
            
            # Clean up old blocked requests
            self.blocked_requests = deque(
                [req for req in self.blocked_requests if req.timestamp > cutoff_time],
                maxlen=self.config['max_events_per_type']
            )
            
            # Clean up old system metrics
            self.system_metrics = deque(
                [metric for metric in self.system_metrics if metric.timestamp > cutoff_time],
                maxlen=1000
            )
            
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
    
    async def _update_statistics(self):
        """Update collection statistics"""
        try:
            self.stats['last_update'] = datetime.utcnow()
            
            # Update suspicious IPs count
            self.stats['total_suspicious_ips'] = len(self.suspicious_ips)
            
        except Exception as e:
            logger.error(f"Error updating statistics: {e}")
    
    async def _broadcast_to_websockets(self, event_type: str, data: Dict[str, Any]):
        """Broadcast data to WebSocket connections"""
        try:
            if not self.config['real_time_updates']:
                return
            
            message = {
                'type': event_type,
                'data': data,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Send to all connected WebSocket clients
            for connection_id, websocket in self.websocket_connections.items():
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Error sending to WebSocket {connection_id}: {e}")
                    # Remove failed connection
                    del self.websocket_connections[connection_id]
                    
        except Exception as e:
            logger.error(f"Error broadcasting to WebSockets: {e}")
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        try:
            # Get recent threats
            recent_threats = sorted(self.threat_events, key=lambda x: x.timestamp, reverse=True)[:50]
            
            # Get recent auth abuse
            recent_auth_abuse = sorted(self.auth_abuse_events, key=lambda x: x.timestamp, reverse=True)[:50]
            
            # Get top suspicious IPs
            top_suspicious_ips = sorted(
                self.suspicious_ips.values(),
                key=lambda x: x.reputation_score,
                reverse=True
            )[:50]
            
            # Get recent WebSocket alerts
            recent_websocket_alerts = sorted(self.websocket_alerts, key=lambda x: x.timestamp, reverse=True)[:50]
            
            # Get recent blocked requests
            recent_blocked_requests = sorted(self.blocked_requests, key=lambda x: x.timestamp, reverse=True)[:50]
            
            # Get system metrics
            recent_system_metrics = sorted(self.system_metrics, key=lambda x: x.timestamp, reverse=True)[:100]
            
            return {
                'statistics': self.stats,
                'live_threats': [
                    {
                        'event_id': event.event_id,
                        'threat_type': event.threat_type,
                        'severity': event.severity.value,
                        'status': event.status.value,
                        'timestamp': event.timestamp.isoformat(),
                        'source_ip': event.source_ip,
                        'target_user': event.target_user,
                        'description': event.description,
                        'confidence': event.confidence,
                        'blocked': event.blocked
                    }
                    for event in recent_threats
                ],
                'auth_abuse': [
                    {
                        'event_id': event.event_id,
                        'user_id': event.user_id,
                        'ip_address': event.ip_address,
                        'abuse_type': event.abuse_type,
                        'severity': event.severity.value,
                        'attempts': event.attempts,
                        'blocked': event.blocked,
                        'timestamp': event.timestamp.isoformat()
                    }
                    for event in recent_auth_abuse
                ],
                'suspicious_ips': [
                    {
                        'ip_address': ip.ip_address,
                        'reputation_score': ip.reputation_score,
                        'threat_level': ip.threat_level.value,
                        'total_requests': ip.total_requests,
                        'blocked_requests': ip.blocked_requests,
                        'countries': ip.countries,
                        'attack_types': ip.attack_types,
                        'last_seen': ip.last_seen.isoformat()
                    }
                    for ip in top_suspicious_ips
                ],
                'websocket_alerts': [
                    {
                        'alert_id': alert.alert_id,
                        'connection_id': alert.connection_id,
                        'client_ip': alert.client_ip,
                        'alert_type': alert.alert_type,
                        'severity': alert.severity.value,
                        'description': alert.description,
                        'resolved': alert.resolved,
                        'timestamp': alert.timestamp.isoformat()
                    }
                    for alert in recent_websocket_alerts
                ],
                'blocked_requests': [
                    {
                        'request_id': request.request_id,
                        'ip_address': request.ip_address,
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'block_reason': request.block_reason,
                        'severity': request.severity.value,
                        'timestamp': request.timestamp.isoformat()
                    }
                    for request in recent_blocked_requests
                ],
                'system_load': [
                    {
                        'metric_name': metric.metric_name,
                        'value': metric.value,
                        'unit': metric.unit,
                        'threshold': metric.threshold,
                        'status': metric.status,
                        'timestamp': metric.timestamp.isoformat()
                    }
                    for metric in recent_system_metrics
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {'error': str(e)}


class SOCDashboardServer:
    """SOC dashboard server with WebSocket support"""
    
    def __init__(self):
        """Initialize SOC dashboard server"""
        self.data_collector = SOCDashboardDataCollector()
        self.websocket_server = None
        self.port = 8080
        self.host = '0.0.0.0'
        self.is_running = False
        
        logger.info("SOC dashboard server initialized")
    
    async def start(self):
        """Start SOC dashboard server"""
        logger.info(f"Starting SOC dashboard server on {self.host}:{self.port}")
        
        try:
            # Start data collection
            await self.data_collector.start_collection()
            
            # Start WebSocket server
            from fastapi import FastAPI, WebSocket
            from fastapi.responses import HTMLResponse
            import uvicorn
            
            app = FastAPI()
            
            @app.get("/")
            async def get_dashboard():
                """Serve dashboard HTML"""
                return HTMLResponse(self._get_dashboard_html())
            
            @app.websocket("/ws")
            async def websocket_endpoint(websocket: WebSocket):
                """WebSocket endpoint for real-time updates"""
                await self._handle_websocket(websocket)
            
            @app.get("/api/dashboard")
            async def get_dashboard_api():
                """Get dashboard data API"""
                return await self.data_collector.get_dashboard_data()
            
            @app.get("/api/threats")
            async def get_threats():
                """Get threats API"""
                data = await self.data_collector.get_dashboard_data()
                return data.get('live_threats', [])
            
            @app.get("/api/auth-abuse")
            async def get_auth_abuse():
                """Get auth abuse API"""
                data = await self.data_collector.get_dashboard_data()
                return data.get('auth_abuse', [])
            
            @app.get("/api/suspicious-ips")
            async def get_suspicious_ips():
                """Get suspicious IPs API"""
                data = await self.data_collector.get_dashboard_data()
                return data.get('suspicious_ips', [])
            
            @app.get("/api/websocket-alerts")
            async def get_websocket_alerts():
                """Get WebSocket alerts API"""
                data = await self.data_collector.get_dashboard_data()
                return data.get('websocket_alerts', [])
            
            @app.get("/api/blocked-requests")
            async def get_blocked_requests():
                """Get blocked requests API"""
                data = await self.data_collector.get_dashboard_data()
                return data.get('blocked_requests', [])
            
            @app.get("/api/system-load")
            async def get_system_load():
                """Get system load API"""
                data = await self.data_collector.get_dashboard_data()
                return data.get('system_load', [])
            
            @app.get("/api/grafana")
            async def get_grafana_data():
                """Get Grafana-compatible data"""
                return await self._get_grafana_data()
            
            # Start server
            config = uvicorn.Config(
                app=app,
                host=self.host,
                port=self.port,
                log_level="info"
            )
            
            server = uvicorn.Server(config)
            await server.serve()
            
        except Exception as e:
            logger.error(f"Error starting SOC dashboard server: {e}")
            raise
    
    async def _handle_websocket(self, websocket: WebSocket):
        """Handle WebSocket connection"""
        try:
            await websocket.accept()
            
            # Generate connection ID
            connection_id = f"ws_{int(time.time())}_{len(self.data_collector.websocket_connections)}"
            
            # Add to connections
            self.data_collector.websocket_connections[connection_id] = websocket
            
            logger.info(f"WebSocket connected: {connection_id}")
            
            # Keep connection alive
            try:
                while True:
                    message = await websocket.receive_text()
                    # Handle incoming messages if needed
                    pass
            except Exception as e:
                logger.error(f"WebSocket error for {connection_id}: {e}")
            finally:
                # Remove connection
                if connection_id in self.data_collector.websocket_connections:
                    del self.data_collector.websocket_connections[connection_id]
                logger.info(f"WebSocket disconnected: {connection_id}")
                
        except Exception as e:
            logger.error(f"Error handling WebSocket: {e}")
    
    def _get_dashboard_html(self) -> str:
        """Get dashboard HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MARY V5 SHIELD CORE - SOC Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            overflow-x: hidden;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            grid-template-rows: auto auto auto;
            gap: 20px;
            padding: 20px;
            min-height: 100vh;
        }
        
        .header {
            grid-column: 1 / -1;
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }
        
        .panel {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .panel-header {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 15px;
            color: #00ff88;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #00ff88;
        }
        
        .status-indicator.critical {
            background: #ff4444;
        }
        
        .status-indicator.high {
            background: #ff8800;
        }
        
        .status-indicator.medium {
            background: #ffaa00;
        }
        
        .status-indicator.low {
            background: #00ff88;
        }
        
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #ffffff;
            margin: 10px 0;
        }
        
        .metric-label {
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
        }
        
        .list-item {
            padding: 8px 0;
            border-bottom: 1px solid #333;
            font-size: 12px;
        }
        
        .list-item:last-child {
            border-bottom: none;
        }
        
        .severity-critical {
            color: #ff4444;
        }
        
        .severity-high {
            color: #ff8800;
        }
        
        .severity-medium {
            color: #ffaa00;
        }
        
        .severity-low {
            color: #00ff88;
        }
        
        .timestamp {
            color: #666;
            font-size: 10px;
        }
        
        .chart-container {
            height: 200px;
            margin-top: 10px;
        }
        
        .heatmap-container {
            height: 300px;
            margin-top: 10px;
        }
        
        .timeline-container {
            max-height: 400px;
            overflow-y: auto;
        }
        
        @media (max-width: 1200px) {
            .dashboard {
                grid-template-columns: 1fr 1fr;
            }
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>MARY V5 SHIELD CORE - SOC DASHBOARD</h1>
            <div id="system-status">System Status: ONLINE</div>
        </div>
        
        <!-- Live Threats Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>Live Threats</span>
                <div class="status-indicator" id="threats-status"></div>
            </div>
            <div class="metric-value" id="threats-count">0</div>
            <div class="metric-label">Active Threats</div>
            <div class="list-container" id="threats-list"></div>
        </div>
        
        <!-- Auth Abuse Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>Auth Abuse</span>
                <div class="status-indicator" id="auth-status"></div>
            </div>
            <div class="metric-value" id="auth-count">0</div>
            <div class="metric-label">Failed Attempts</div>
            <div class="list-container" id="auth-list"></div>
        </div>
        
        <!-- Suspicious IPs Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>Suspicious IPs</span>
                <div class="status-indicator" id="ip-status"></div>
            </div>
            <div class="metric-value" id="ip-count">0</div>
            <div class="metric-label">Tracked IPs</div>
            <div class="list-container" id="ip-list"></div>
        </div>
        
        <!-- WebSocket Alerts Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>WebSocket Alerts</span>
                <div class="status-indicator" id="ws-status"></div>
            </div>
            <div class="metric-value" id="ws-count">0</div>
            <div class="metric-label">Active Alerts</div>
            <div class="list-container" id="ws-list"></div>
        </div>
        
        <!-- Attack Heatmap Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>Attack Heatmap</span>
                <div class="status-indicator" id="heatmap-status"></div>
            </div>
            <div class="heatmap-container">
                <canvas id="attack-heatmap"></canvas>
            </div>
        </div>
        
        <!-- Timeline View Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>Timeline View</span>
                <div class="status-indicator" id="timeline-status"></div>
            </div>
            <div class="timeline-container" id="timeline-list"></div>
        </div>
        
        <!-- Blocked Requests Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>Blocked Requests</span>
                <div class="status-indicator" id="blocked-status"></div>
            </div>
            <div class="metric-value" id="blocked-count">0</div>
            <div class="metric-label">Blocked</div>
            <div class="list-container" id="blocked-list"></div>
        </div>
        
        <!-- System Load Panel -->
        <div class="panel">
            <div class="panel-header">
                <span>System Load</span>
                <div class="status-indicator" id="load-status"></div>
            </div>
            <div class="chart-container">
                <canvas id="load-chart"></canvas>
            </div>
        </div>
    </div>
    
    <script>
        // WebSocket connection
        const ws = new WebSocket('ws://localhost:8080/ws');
        
        // Chart configurations
        const loadChart = new Chart(document.getElementById('load-chart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU Usage',
                    data: [],
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Memory Usage',
                    data: [],
                    borderColor: '#ff8800',
                    backgroundColor: 'rgba(255, 136, 0, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: { color: '#888' },
                        grid: { color: '#333' }
                    },
                    x: {
                        ticks: { color: '#888' },
                        grid: { color: '#333' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                }
            }
        });
        
        // Heatmap configuration
        const heatmapData = {
            labels: ['Americas', 'Europe', 'Asia', 'Africa', 'Oceania'],
            datasets: [{
                label: 'Attacks',
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(255, 68, 68, 0.8)',
                    'rgba(255, 136, 0, 0.8)',
                    'rgba(255, 170, 0, 0.8)',
                    'rgba(0, 255, 136, 0.8)',
                    'rgba(68, 136, 255, 0.8)'
                ]
            }]
        };
        
        const attackHeatmap = new Chart(document.getElementById('attack-heatmap'), {
            type: 'bar',
            data: heatmapData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#888' },
                        grid: { color: '#333' }
                    },
                    x: {
                        ticks: { color: '#888' },
                        grid: { color: '#333' }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#fff' }
                    }
                }
            }
        });
        
        // WebSocket message handler
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            switch(data.type) {
                case 'threat_event':
                    updateThreatsList(data.data);
                    break;
                case 'auth_abuse':
                    updateAuthList(data.data);
                    break;
                case 'suspicious_ip':
                    updateIPList(data.data);
                    break;
                case 'websocket_alert':
                    updateWebSocketList(data.data);
                    break;
                case 'blocked_request':
                    updateBlockedList(data.data);
                    break;
                case 'system_metric':
                    updateSystemLoad(data.data);
                    break;
            }
        };
        
        // Update functions
        function updateThreatsList(data) {
            const container = document.getElementById('threats-list');
            const count = document.getElementById('threats-count');
            const status = document.getElementById('threats-status');
            
            container.innerHTML = data.slice(0, 10).map(threat => `
                <div class="list-item">
                    <span class="severity-${threat.severity}">${threat.threat_type}</span>
                    <div>${threat.description}</div>
                    <div class="timestamp">${new Date(threat.timestamp).toLocaleTimeString()}</div>
                </div>
            `).join('');
            
            count.textContent = data.length;
            status.className = `status-indicator ${data.length > 0 ? 'high' : 'low'}`;
        }
        
        function updateAuthList(data) {
            const container = document.getElementById('auth-list');
            const count = document.getElementById('auth-count');
            const status = document.getElementById('auth-status');
            
            container.innerHTML = data.slice(0, 10).map(auth => `
                <div class="list-item">
                    <span class="severity-${auth.severity}">${auth.user_id}</span>
                    <div>${auth.abuse_type} - ${auth.ip_address}</div>
                    <div class="timestamp">${new Date(auth.timestamp).toLocaleTimeString()}</div>
                </div>
            `).join('');
            
            count.textContent = data.length;
            status.className = `status-indicator ${data.length > 0 ? 'high' : 'low'}`;
        }
        
        function updateIPList(data) {
            const container = document.getElementById('ip-list');
            const count = document.getElementById('ip-count');
            const status = document.getElementById('ip-status');
            
            container.innerHTML = data.slice(0, 10).map(ip => `
                <div class="list-item">
                    <span class="severity-${ip.threat_level}">${ip.ip_address}</span>
                    <div>Score: ${ip.reputation_score.toFixed(2)}</div>
                    <div class="timestamp">${new Date(ip.last_seen).toLocaleTimeString()}</div>
                </div>
            `).join('');
            
            count.textContent = data.length;
            status.className = `status-indicator ${data.length > 0 ? 'high' : 'low'}`;
        }
        
        function updateWebSocketList(data) {
            const container = document.getElementById('ws-list');
            const count = document.getElementById('ws-count');
            const status = document.getElementById('ws-status');
            
            container.innerHTML = data.slice(0, 10).map(alert => `
                <div class="list-item">
                    <span class="severity-${alert.severity}">${alert.alert_type}</span>
                    <div>${alert.client_ip} - ${alert.connection_id}</div>
                    <div class="timestamp">${new Date(alert.timestamp).toLocaleTimeString()}</div>
                </div>
            `).join('');
            
            count.textContent = data.length;
            status.className = `status-indicator ${data.length > 0 ? 'medium' : 'low'}`;
        }
        
        function updateBlockedList(data) {
            const container = document.getElementById('blocked-list');
            const count = document.getElementById('blocked-count');
            const status = document.getElementById('blocked-status');
            
            container.innerHTML = data.slice(0, 10).map(req => `
                <div class="list-item">
                    <span class="severity-${req.severity}">${req.ip_address}</span>
                    <div>${req.method} ${req.endpoint}</div>
                    <div>${req.block_reason}</div>
                    <div class="timestamp">${new Date(req.timestamp).toLocaleTimeString()}</div>
                </div>
            `).join('');
            
            count.textContent = data.length;
            status.className = `status-indicator ${data.length > 0 ? 'critical' : 'low'}`;
        }
        
        function updateSystemLoad(data) {
            if (data.metric_name === 'cpu_usage' || data.metric_name === 'memory_usage') {
                const dataset = data.metric_name === 'cpu_usage' ? 0 : 1;
                
                // Update chart
                if (loadChart.data.labels.length > 50) {
                    loadChart.data.labels.shift();
                    loadChart.data.datasets[dataset].data.shift();
                }
                
                loadChart.data.labels.push(new Date().toLocaleTimeString());
                loadChart.data.datasets[dataset].data.push(data.value);
                loadChart.update();
            }
        }
        
        // Load initial data
        async function loadInitialData() {
            try {
                const response = await fetch('/api/dashboard');
                const data = await response.json();
                
                updateThreatsList(data.live_threats);
                updateAuthList(data.auth_abuse);
                updateIPList(data.suspicious_ips);
                updateWebSocketList(data.websocket_alerts);
                updateBlockedList(data.blocked_requests);
                
                // Initialize system load chart
                data.system_load.forEach(metric => {
                    if (metric.metric_name === 'cpu_usage' || metric.metric_name === 'memory_usage') {
                        const dataset = metric.metric_name === 'cpu_usage' ? 0 : 1;
                        loadChart.data.labels.push(new Date().toLocaleTimeString());
                        loadChart.data.datasets[dataset].data.push(metric.value);
                    }
                });
                loadChart.update();
                
            } catch (error) {
                console.error('Error loading initial data:', error);
            }
        }
        
        // Initialize dashboard
        loadInitialData();
        
        // Update system status
        setInterval(() => {
            const status = document.getElementById('system-status');
            const now = new Date();
            status.textContent = `System Status: ONLINE | ${now.toLocaleTimeString()}`;
        }, 1000);
    </script>
</body>
</html>
        """
    
    async def _get_grafana_data(self) -> void:
        """Get Grafana-compatible data"""
        try:
            dashboard_data = await self.data_collector.get_dashboard_data()
            
            # Transform data for Grafana
            grafana_data = {
                'threats': {
                    'total': len(dashboard_data.get('live_threats', [])),
                    'critical': len([t for t in dashboard_data.get('live_threats', []) if t.get('severity') == 'critical']),
                    'high': len([t for t in dashboard_data.get('live_threats', []) if t.get('severity') == 'high']),
                    'medium': len([t for t in dashboard_data.get('live_threats', []) if t.get('severity') == 'medium']),
                    'low': len([t for t in dashboard_data.get('live_threats', []) if t.get('severity') == 'low'])
                },
                'auth_abuse': {
                    'total': len(dashboard_data.get('auth_abuse', [])),
                    'blocked': len([a for a in dashboard_data.get('auth_abuse', []) if a.get('blocked')]),
                    'attempts': sum([a.get('attempts', 0) for a in dashboard_data.get('auth_abuse', [])])
                },
                'suspicious_ips': {
                    'total': len(dashboard_data.get('suspicious_ips', [])),
                    'high_risk': len([ip for ip in dashboard_data.get('suspicious_ips', []) if ip.get('threat_level') == 'critical']),
                    'medium_risk': len([ip for ip in dashboard_data.get('suspicious_ips', []) if ip.get('threat_level') == 'high']),
                    'low_risk': len([ip for ip in dashboard_data.get('suspicious_ips', []) if ip.get('threat_level') == 'medium'])
                },
                'websocket_alerts': {
                    'total': len(dashboard_data.get('websocket_alerts', [])),
                    'active': len([a for a in dashboard_data.get('websocket_alerts', []) if not a.get('resolved')]),
                    'resolved': len([a for a in dashboard_data.get('websocket_alerts', []) if a.get('resolved')])
                },
                'blocked_requests': {
                    'total': len(dashboard_data.get('blocked_requests', [])),
                    'critical': len([r for r in dashboard_data.get('blocked_requests', []) if r.get('severity') == 'critical']),
                    'high': len([r for r in dashboard_data.get('blocked_requests', []) if r.get('severity') == 'high']),
                    'medium': len([r for r in dashboard_data.get('blocked_requests', []) if r.get('severity') == 'medium']),
                    'low': len([r for r in dashboard_data.get('blocked_requests', []) if r.get('severity') == 'low'])
                },
                'system_load': {
                    'cpu_usage': next((m['value'] for m in dashboard_data.get('system_load', []) if m.get('metric_name') == 'cpu_usage'), 0),
                    'memory_usage': next((m['value'] for m in dashboard_data.get('system_load', []) if m.get('metric_name') == 'memory_usage'), 0),
                    'disk_usage': next((m['value'] for m in dashboard_data.get('system_load', []) if m.get('metric_name') == 'disk_usage'), 0),
                    'network_io': next((m['value'] for m in dashboard_data.get('system_load', []) if m.get('metric_name') == 'network_io'), 0)
                },
                'statistics': dashboard_data.get('statistics', {}),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return grafana_data
            
        except Exception as e:
            logger.error(f"Error getting Grafana data: {e}")
            return {'error': str(e)}


# Global SOC dashboard instance
soc_dashboard_server = SOCDashboardServer()


# API functions
async def initialize_soc_dashboard() -> str:
    """Initialize SOC dashboard"""
    try:
        # Start dashboard in background
        asyncio.create_task(soc_dashboard_server.start())
        logger.info("SOC dashboard initialized")
        return "SOC dashboard initialized on http://localhost:8080"
    except Exception as e:
        logger.error(f"Error initializing SOC dashboard: {e}")
        return f"Error initializing SOC dashboard: {e}"


async def get_soc_dashboard_data() -> Dict[str, Any]:
    """Get SOC dashboard data"""
    try:
        return await soc_dashboard_server.data_collector.get_dashboard_data()
    except Exception as e:
        logger.error(f"Error getting SOC dashboard data: {e}")
        return {'error': str(e)}


async def add_threat_event(event_data: Dict[str, Any]) -> str:
    """Add threat event to dashboard"""
    try:
        threat_event = ThreatEvent(
            event_id=event_data.get('event_id', f"threat_{int(time.time())}"),
            threat_type=event_data.get('threat_type', 'unknown'),
            severity=ThreatSeverity(event_data.get('severity', 'medium')),
            status=AlertStatus(event_data.get('status', 'active')),
            timestamp=datetime.fromisoformat(event_data.get('timestamp', datetime.utcnow().isoformat())),
            source_ip=event_data.get('source_ip', ''),
            target_user=event_data.get('target_user'),
            description=event_data.get('description', ''),
            details=event_data.get('details', {}),
            confidence=event_data.get('confidence', 0.5),
            blocked=event_data.get('blocked', False),
            resolved_at=datetime.fromisoformat(event_data['resolved_at']) if event_data.get('resolved_at') else None,
            assigned_to=event_data.get('assigned_to'),
            tags=event_data.get('tags', []),
            metadata=event_data.get('metadata', {})
        )
        
        await soc_dashboard_server.data_collector.add_threat_event(threat_event)
        return f"Threat event added: {threat_event.event_id}"
        
    except Exception as e:
        logger.error(f"Error adding threat event: {e}")
        return f"Error adding threat event: {e}"


async def add_auth_abuse_event(abuse_data: Dict[str, Any]) -> str:
    """Add auth abuse event to dashboard"""
    try:
        auth_event = AuthAbuseEvent(
            event_id=abuse_data.get('event_id', f"auth_{int(time.time())}"),
            user_id=abuse_data.get('user_id', ''),
            ip_address=abuse_data.get('ip_address', ''),
            user_agent=abuse_data.get('user_agent', ''),
            location=abuse_data.get('location', {}),
            timestamp=datetime.fromisoformat(abuse_data.get('timestamp', datetime.utcnow().isoformat())),
            abuse_type=abuse_data.get('abuse_type', 'unknown'),
            severity=ThreatSeverity(abuse_data.get('severity', 'medium')),
            attempts=abuse_data.get('attempts', 1),
            blocked=abuse_data.get('blocked', False),
            details=abuse_data.get('details', {})
        )
        
        await soc_dashboard_server.data_collector.add_auth_abuse_event(auth_event)
        return f"Auth abuse event added: {auth_event.event_id}"
        
    except Exception as e:
        logger.error(f"Error adding auth abuse event: {e}")
        return f"Error adding auth abuse event: {e}"


async def add_suspicious_ip(ip_data: Dict[str, Any]) -> str:
    """Add suspicious IP to dashboard"""
    try:
        await soc_dashboard_server.data_collector.add_suspicious_ip(ip_data)
        return f"Suspicious IP added: {ip_data.get('ip_address', 'unknown')}"
        
    except Exception as e:
        logger.error(f"Error adding suspicious IP: {e}")
        return f"Error adding suspicious IP: {e}"


async def add_websocket_alert(alert_data: Dict[str, Any]) -> str:
    """Add WebSocket alert to dashboard"""
    try:
        alert = WebSocketAlert(
            alert_id=alert_data.get('alert_id', f"ws_{int(time.time())}"),
            connection_id=alert_data.get('connection_id', ''),
            client_ip=alert_data.get('client_ip', ''),
            alert_type=alert_data.get('alert_type', 'unknown'),
            severity=ThreatSeverity(alert_data.get('severity', 'medium')),
            timestamp=datetime.fromisoformat(alert_data.get('timestamp', datetime.utcnow().isoformat())),
            description=alert_data.get('description', ''),
            details=alert_data.get('details', {}),
            resolved=alert_data.get('resolved', False)
        )
        
        await soc_dashboard_server.data_collector.add_websocket_alert(alert)
        return f"WebSocket alert added: {alert.alert_id}"
        
    except Exception as e:
        logger.error(f"Error adding WebSocket alert: {e}")
        return f"Error adding WebSocket alert: {e}"


async def add_blocked_request(request_data: Dict[str, Any]) -> str:
    """Add blocked request to dashboard"""
    try:
        request = BlockedRequest(
            request_id=request_data.get('request_id', f"blocked_{int(time.time())}"),
            timestamp=datetime.fromisoformat(request_data.get('timestamp', datetime.utcnow().isoformat())),
            ip_address=request_data.get('ip_address', ''),
            endpoint=request_data.get('endpoint', ''),
            method=request_data.get('method', 'GET'),
            user_agent=request_data.get('user_agent', ''),
            block_reason=request_data.get('block_reason', 'unknown'),
            severity=ThreatSeverity(request_data.get('severity', 'medium')),
            details=request_data.get('details', {})
        )
        
        await soc_dashboard_server.data_collector.add_blocked_request(request)
        return f"Blocked request added: {request.request_id}"
        
    except Exception as e:
        logger.error(f"Error adding blocked request: {e}")
        return f"Error adding blocked request: {e}"


async def get_grafana_metrics() -> Dict[str, Any]:
    """Get Grafana-compatible metrics"""
    try:
        return await soc_dashboard_server._get_grafana_data()
    except Exception as e:
        logger.error(f"Error getting Grafana metrics: {e}")
        return {'error': str(e)}
