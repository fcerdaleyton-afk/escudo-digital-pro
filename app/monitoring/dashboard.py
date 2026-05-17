"""
Real-time Monitoring Dashboard for Mary V5 Enterprise
Live alerts, attack scoring, and threat timeline visualization
"""

import os
import json
import asyncio
import websockets
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum
import redis.asyncio as redis

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event
from app.detection.threat_engine import get_threat_detection_engine, ThreatType, ThreatSeverity


class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class DashboardAlert:
    """Dashboard alert data structure"""
    id: str
    level: AlertLevel
    title: str
    message: str
    timestamp: datetime
    source: str
    details: Dict[str, Any]
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class AttackScore:
    """Attack scoring metrics"""
    overall_score: float
    threat_score: float
    anomaly_score: float
    volume_score: float
    timestamp: datetime
    factors: List[str]


@dataclass
class ResourceMetrics:
    """System resource metrics"""
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_io: Dict[str, int]
    active_connections: int
    timestamp: datetime


class RealtimeDashboard:
    """Real-time monitoring dashboard"""
    
    def __init__(self):
        self.enabled = os.getenv("REALTIME_DASHBOARD_ENABLED", "true").lower() == "true"
        self.websocket_port = int(os.getenv("WEBSOCKET_PORT", "8765"))
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        
        # WebSocket connections
        self.active_connections: Set[websockets.WebSocketServerProtocol] = set()
        
        # Dashboard data
        self.alerts = deque(maxlen=1000)
        self.attack_scores = deque(maxlen=100)
        self.resource_metrics = deque(maxlen=100)
        self.threat_timeline = deque(maxlen=500)
        
        # Alert thresholds
        self.alert_thresholds = {
            "threat_score": float(os.getenv("THREAT_ALERT_THRESHOLD", "70.0")),
            "cpu_usage": float(os.getenv("CPU_ALERT_THRESHOLD", "90.0")),
            "memory_usage": float(os.getenv("MEMORY_ALERT_THRESHOLD", "85.0")),
            "error_rate": float(os.getenv("ERROR_RATE_THRESHOLD", "5.0"))
        }
        
        # Redis client for pub/sub
        self.redis_client = None
        self.pubsub = None
        
        logger.info("Real-time dashboard initialized", enabled=self.enabled)
    
    async def initialize(self):
        """Initialize dashboard components"""
        if not self.enabled:
            return
        
        try:
            # Initialize Redis
            self.redis_client = await redis.from_url(self.redis_url)
            self.pubsub = self.redis_client.pubsub()
            
            # Subscribe to security events
            await self.pubsub.subscribe("security_events", "threat_alerts", "system_metrics")
            
            logger.info("Dashboard initialized successfully")
            
        except Exception as e:
            logger.error("Dashboard initialization failed", error=str(e))
    
    async def start_websocket_server(self):
        """Start WebSocket server for real-time updates"""
        if not self.enabled:
            return
        
        async def handle_websocket(websocket, path):
            """Handle WebSocket connections"""
            self.active_connections.add(websocket)
            
            try:
                # Send initial dashboard state
                await self.send_initial_state(websocket)
                
                # Keep connection alive
                await websocket.wait_closed()
                
            except websockets.exceptions.ConnectionClosed:
                pass
            finally:
                self.active_connections.discard(websocket)
        
        # Start WebSocket server
        server = await websockets.serve(handle_websocket, "0.0.0.0", self.websocket_port)
        logger.info(f"WebSocket server started on port {self.websocket_port}")
        
        return server
    
    async def send_initial_state(self, websocket):
        """Send initial dashboard state to new connection"""
        initial_state = {
            "type": "initial_state",
            "data": {
                "alerts": [asdict(alert) for alert in list(self.alerts)[-50:]],
                "attack_scores": [asdict(score) for score in list(self.attack_scores)[-20:]],
                "resource_metrics": [asdict(metric) for metric in list(self.resource_metrics)[-30:]],
                "threat_timeline": [asdict(event) for event in list(self.threat_timeline)[-100:]],
                "dashboard_stats": self.get_dashboard_stats()
            }
        }
        
        await websocket.send(json.dumps(initial_state, default=str))
    
    async def broadcast_update(self, update_type: str, data: Dict[str, Any]):
        """Broadcast update to all connected clients"""
        if not self.active_connections:
            return
        
        message = {
            "type": update_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        
        # Send to all connected clients
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send(json.dumps(message, default=str))
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(connection)
        
        # Remove disconnected clients
        self.active_connections -= disconnected
    
    async def add_alert(self, level: AlertLevel, title: str, message: str, 
                       source: str, details: Dict[str, Any] = None):
        """Add new alert to dashboard"""
        alert = DashboardAlert(
            id=f"alert_{int(datetime.utcnow().timestamp())}",
            level=level,
            title=title,
            message=message,
            timestamp=datetime.utcnow(),
            source=source,
            details=details or {}
        )
        
        self.alerts.append(alert)
        
        # Broadcast to clients
        await self.broadcast_update("new_alert", asdict(alert))
        
        # Log alert
        log_security_event(
            "dashboard_alert",
            {
                "alert_id": alert.id,
                "level": alert.level.value,
                "title": alert.title,
                "source": alert.source
            }
        )
    
    async def update_attack_score(self, threat_score: float, anomaly_score: float, 
                                volume_score: float, factors: List[str]):
        """Update attack score metrics"""
        overall_score = (threat_score * 0.5 + anomaly_score * 0.3 + volume_score * 0.2)
        
        attack_score = AttackScore(
            overall_score=overall_score,
            threat_score=threat_score,
            anomaly_score=anomaly_score,
            volume_score=volume_score,
            timestamp=datetime.utcnow(),
            factors=factors
        )
        
        self.attack_scores.append(attack_score)
        
        # Broadcast to clients
        await self.broadcast_update("attack_score_update", asdict(attack_score))
        
        # Check for alerts
        if overall_score >= self.alert_thresholds["threat_score"]:
            await self.add_alert(
                AlertLevel.CRITICAL,
                "High Attack Score Detected",
                f"Attack score: {overall_score:.2f}",
                "threat_detection",
                {"score": overall_score, "factors": factors}
            )
    
    async def update_resource_metrics(self, cpu: float, memory: float, disk: float, 
                                    network_io: Dict[str, int], connections: int):
        """Update resource metrics"""
        metrics = ResourceMetrics(
            cpu_percent=cpu,
            memory_percent=memory,
            disk_percent=disk,
            network_io=network_io,
            active_connections=connections,
            timestamp=datetime.utcnow()
        )
        
        self.resource_metrics.append(metrics)
        
        # Broadcast to clients
        await self.broadcast_update("resource_metrics_update", asdict(metrics))
        
        # Check for alerts
        if cpu >= self.alert_thresholds["cpu_usage"]:
            await self.add_alert(
                AlertLevel.WARNING,
                "High CPU Usage",
                f"CPU usage: {cpu:.1f}%",
                "system_monitor",
                {"cpu_percent": cpu}
            )
        
        if memory >= self.alert_thresholds["memory_usage"]:
            await self.add_alert(
                AlertLevel.WARNING,
                "High Memory Usage",
                f"Memory usage: {memory:.1f}%",
                "system_monitor",
                {"memory_percent": memory}
            )
    
    async def add_threat_event(self, threat_type: str, severity: str, description: str, 
                             evidence: Dict[str, Any]):
        """Add threat event to timeline"""
        threat_event = {
            "id": f"threat_{int(datetime.utcnow().timestamp())}",
            "type": threat_type,
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow(),
            "evidence": evidence
        }
        
        self.threat_timeline.append(threat_event)
        
        # Broadcast to clients
        await self.broadcast_update("threat_event", threat_event)
        
        # Check for alerts
        if severity in ["high", "critical"]:
            level = AlertLevel.CRITICAL if severity == "critical" else AlertLevel.WARNING
            await self.add_alert(
                level,
                f"Threat Detected: {threat_type}",
                description,
                "threat_detection",
                {"threat_type": threat_type, "severity": severity}
            )
    
    async def process_redis_messages(self):
        """Process Redis pub/sub messages"""
        if not self.pubsub:
            return
        
        async for message in self.pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    channel = message["channel"]
                    
                    if channel == "security_events":
                        await self.process_security_event(data)
                    elif channel == "threat_alerts":
                        await self.process_threat_alert(data)
                    elif channel == "system_metrics":
                        await self.process_system_metrics(data)
                
                except Exception as e:
                    logger.error("Error processing Redis message", error=str(e))
    
    async def process_security_event(self, event_data: Dict[str, Any]):
        """Process security event from Redis"""
        event_type = event_data.get("event_type", "")
        
        if event_type in ["ransomware_detected", "malware_detected"]:
            await self.add_threat_event(
                event_type,
                event_data.get("severity", "medium"),
                event_data.get("description", ""),
                event_data.get("evidence", {})
            )
    
    async def process_threat_alert(self, alert_data: Dict[str, Any]):
        """Process threat alert from Redis"""
        threat_score = alert_data.get("threat_score", 0)
        anomaly_score = alert_data.get("anomaly_score", 0)
        volume_score = alert_data.get("volume_score", 0)
        factors = alert_data.get("factors", [])
        
        await self.update_attack_score(threat_score, anomaly_score, volume_score, factors)
    
    async def process_system_metrics(self, metrics_data: Dict[str, Any]):
        """Process system metrics from Redis"""
        await self.update_resource_metrics(
            metrics_data.get("cpu_percent", 0),
            metrics_data.get("memory_percent", 0),
            metrics_data.get("disk_percent", 0),
            metrics_data.get("network_io", {}),
            metrics_data.get("active_connections", 0)
        )
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics"""
        current_time = datetime.utcnow()
        
        # Count alerts by level
        alert_counts = defaultdict(int)
        for alert in self.alerts:
            alert_counts[alert.level.value] += 1
        
        # Recent threats (last hour)
        hour_ago = current_time - timedelta(hours=1)
        recent_threats = [
            threat for threat in self.threat_timeline
            if threat["timestamp"] > hour_ago
        ]
        
        # Current attack score
        current_attack_score = (
            self.attack_scores[-1].overall_score 
            if self.attack_scores else 0
        )
        
        return {
            "total_alerts": len(self.alerts),
            "alert_counts": dict(alert_counts),
            "active_connections": len(self.active_connections),
            "recent_threats": len(recent_threats),
            "current_attack_score": current_attack_score,
            "enabled": self.enabled
        }
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get complete dashboard data"""
        return {
            "alerts": [asdict(alert) for alert in list(self.alerts)[-100:]],
            "attack_scores": [asdict(score) for score in list(self.attack_scores)[-50:]],
            "resource_metrics": [asdict(metric) for metric in list(self.resource_metrics)[-100:]],
            "threat_timeline": [asdict(event) for event in list(self.threat_timeline)[-200:]],
            "stats": self.get_dashboard_stats()
        }


class PrometheusMetrics:
    """Prometheus metrics integration"""
    
    def __init__(self):
        self.enabled = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
        
        # Metrics definitions
        self.metrics = {
            "threat_events_total": 0,
            "security_alerts_total": 0,
            "attack_score": 0.0,
            "cpu_usage_percent": 0.0,
            "memory_usage_percent": 0.0,
            "active_websocket_connections": 0
        }
        
        logger.info("Prometheus metrics initialized", enabled=self.enabled)
    
    def increment_counter(self, metric_name: str, value: int = 1):
        """Increment counter metric"""
        if self.enabled and metric_name in self.metrics:
            self.metrics[metric_name] += value
    
    def set_gauge(self, metric_name: str, value: float):
        """Set gauge metric"""
        if self.enabled and metric_name in self.metrics:
            self.metrics[metric_name] = value
    
    def get_metrics_text(self) -> str:
        """Generate Prometheus metrics text format"""
        if not self.enabled:
            return ""
        
        metrics_text = []
        current_time = int(datetime.utcnow().timestamp())
        
        # Counter metrics
        metrics_text.append(f"# HELP threat_events_total Total number of threat events")
        metrics_text.append(f"# TYPE threat_events_total counter")
        metrics_text.append(f"threat_events_total {self.metrics['threat_events_total']} {current_time}")
        
        metrics_text.append(f"# HELP security_alerts_total Total number of security alerts")
        metrics_text.append(f"# TYPE security_alerts_total counter")
        metrics_text.append(f"security_alerts_total {self.metrics['security_alerts_total']} {current_time}")
        
        # Gauge metrics
        metrics_text.append(f"# HELP attack_score Current attack score")
        metrics_text.append(f"# TYPE attack_score gauge")
        metrics_text.append(f"attack_score {self.metrics['attack_score']} {current_time}")
        
        metrics_text.append(f"# HELP cpu_usage_percent CPU usage percentage")
        metrics_text.append(f"# TYPE cpu_usage_percent gauge")
        metrics_text.append(f"cpu_usage_percent {self.metrics['cpu_usage_percent']} {current_time}")
        
        metrics_text.append(f"# HELP memory_usage_percent Memory usage percentage")
        metrics_text.append(f"# TYPE memory_usage_percent gauge")
        metrics_text.append(f"memory_usage_percent {self.metrics['memory_usage_percent']} {current_time}")
        
        metrics_text.append(f"# HELP active_websocket_connections Active WebSocket connections")
        metrics_text.append(f"# TYPE active_websocket_connections gauge")
        metrics_text.append(f"active_websocket_connections {self.metrics['active_websocket_connections']} {current_time}")
        
        return "\n".join(metrics_text)


# Global instances
realtime_dashboard = RealtimeDashboard()
prometheus_metrics = PrometheusMetrics()


async def get_dashboard_data() -> Dict[str, Any]:
    """Get dashboard data"""
    return realtime_dashboard.get_dashboard_data()


async def add_dashboard_alert(level: AlertLevel, title: str, message: str, 
                            source: str, details: Dict[str, Any] = None):
    """Add dashboard alert"""
    await realtime_dashboard.add_alert(level, title, message, source, details)


async def update_attack_score_metrics(threat_score: float, anomaly_score: float, 
                                    volume_score: float, factors: List[str]):
    """Update attack score metrics"""
    await realtime_dashboard.update_attack_score(threat_score, anomaly_score, volume_score, factors)
    prometheus_metrics.set_gauge("attack_score", threat_score)


async def update_resource_metrics(cpu: float, memory: float, disk: float, 
                               network_io: Dict[str, int], connections: int):
    """Update resource metrics"""
    await realtime_dashboard.update_resource_metrics(cpu, memory, disk, network_io, connections)
    prometheus_metrics.set_gauge("cpu_usage_percent", cpu)
    prometheus_metrics.set_gauge("memory_usage_percent", memory)


async def add_threat_timeline_event(threat_type: str, severity: str, description: str, 
                                 evidence: Dict[str, Any]):
    """Add threat event to timeline"""
    await realtime_dashboard.add_threat_event(threat_type, severity, description, evidence)
    prometheus_metrics.increment_counter("threat_events_total")


def get_prometheus_metrics() -> str:
    """Get Prometheus metrics"""
    return prometheus_metrics.get_metrics_text()


async def start_dashboard_services():
    """Start all dashboard services"""
    # Initialize dashboard
    await realtime_dashboard.initialize()
    
    # Start WebSocket server
    websocket_server = await realtime_dashboard.start_websocket_server()
    
    # Start Redis message processing
    redis_task = asyncio.create_task(realtime_dashboard.process_redis_messages())
    
    return websocket_server, redis_task
