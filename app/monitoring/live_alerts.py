"""
MARY V5 SHIELD CORE - Real-time Alert System
Advanced WebSocket-based alert system with SIEM integration
"""

import os
import asyncio
import json
import time
import uuid
from typing import Dict, List, Optional, Any, Set, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
import websockets
import weakref

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class AlertPriority(Enum):
    """Alert priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status lifecycle"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertCategory(Enum):
    """Alert categories"""
    SECURITY = "security"
    PERFORMANCE = "performance"
    SYSTEM = "system"
    NETWORK = "network"
    APPLICATION = "application"
    COMPLIANCE = "compliance"


@dataclass
class LiveAlert:
    """Live alert data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    priority: AlertPriority = AlertPriority.MEDIUM
    category: AlertCategory = AlertCategory.SECURITY
    status: AlertStatus = AlertStatus.NEW
    title: str = ""
    description: str = ""
    source: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['priority'] = self.priority.value
        data['status'] = self.status.value
        data['category'] = self.category.value
        if self.acknowledged_at:
            data['acknowledged_at'] = self.acknowledged_at.isoformat()
        if self.resolved_at:
            data['resolved_at'] = self.resolved_at.isoformat()
        return data
    
    def to_siem_payload(self) -> Dict[str, Any]:
        """Convert to SIEM-ready JSON payload"""
        return {
            "@timestamp": self.timestamp.isoformat() + "Z",
            "event": {
                "id": self.id,
                "kind": "alert",
                "category": [self.category.value],
                "severity": self.priority.value,
                "status": self.status.value,
                "title": self.title,
                "description": self.description,
                "source": self.source
            },
            "source": {
                "ip": self.ip_address,
                "user": {
                    "id": self.user_id
                } if self.user_id else None
            },
            "tags": self.tags,
            "details": self.details,
            "correlation_id": self.correlation_id,
            "session_id": self.session_id
        }


class AlertQueue:
    """Async alert queue with prioritization"""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.queues = {
            AlertPriority.CRITICAL: asyncio.Queue(maxsize=max_size // 4),
            AlertPriority.HIGH: asyncio.Queue(maxsize=max_size // 4),
            AlertPriority.MEDIUM: asyncio.Queue(maxsize // 2),
            AlertPriority.LOW: asyncio.Queue(maxsize=max_size // 2)
        }
        self.total_processed = 0
        self.dropped_alerts = 0
    
    async def put(self, alert: LiveAlert) -> bool:
        """Add alert to appropriate priority queue"""
        try:
            await self.queues[alert.priority].put(alert)
            self.total_processed += 1
            return True
        except asyncio.QueueFull:
            self.dropped_alerts += 1
            logger.warning("Alert queue full, dropping alert", alert_id=alert.id)
            return False
    
    async def get(self) -> Optional[LiveAlert]:
        """Get next alert by priority"""
        # Check queues in priority order
        for priority in [AlertPriority.CRITICAL, AlertPriority.HIGH, AlertPriority.MEDIUM, AlertPriority.LOW]:
            try:
                return await asyncio.wait_for(self.queues[priority].get(), timeout=0.1)
            except asyncio.QueueFull:
                continue
            except asyncio.TimeoutError:
                continue
        return None
    
    def size(self) -> int:
        """Get total queue size"""
        return sum(queue.qsize() for queue in self.queues.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        return {
            "total_processed": self.total_processed,
            "dropped_alerts": self.dropped_alerts,
            "queue_sizes": {
                priority.value: queue.qsize() 
                for priority, queue in self.queues.items()
            },
            "total_size": self.size()
        }


class WebSocketManager:
    """WebSocket connection manager for real-time alerts"""
    
    def __init__(self):
        self.connections: Set[websockets.WebSocketServerProtocol] = weakref.WeakSet()
        self.connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_failed": 0
        }
    
    async def register(self, websocket: websockets.WebSocketServerProtocol):
        """Register new WebSocket connection"""
        self.connections.add(websocket)
        self.connection_stats["total_connections"] += 1
        self.connection_stats["active_connections"] += 1
        
        logger.info("WebSocket client connected", total_connections=self.connection_stats["active_connections"])
        
        # Send welcome message
        await self.send_to_client(websocket, {
            "type": "connection_established",
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Connected to live alert system"
        })
    
    async def unregister(self, websocket: websockets.WebSocketServerProtocol):
        """Unregister WebSocket connection"""
        self.connections.discard(websocket)
        self.connection_stats["active_connections"] -= 1
        
        logger.info("WebSocket client disconnected", active_connections=self.connection_stats["active_connections"])
    
    async def send_to_client(self, websocket: websockets.WebSocketServerProtocol, message: Dict[str, Any]):
        """Send message to specific client"""
        try:
            await websocket.send(json.dumps(message, default=str))
            self.connection_stats["messages_sent"] += 1
        except Exception as e:
            self.connection_stats["messages_failed"] += 1
            logger.error("Failed to send WebSocket message", error=str(e))
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        if not self.connections:
            return
        
        message_str = json.dumps(message, default=str)
        disconnected = set()
        
        for websocket in list(self.connections):
            try:
                await websocket.send(message_str)
                self.connection_stats["messages_sent"] += 1
            except Exception as e:
                self.connection_stats["messages_failed"] += 1
                disconnected.add(websocket)
        
        # Clean up disconnected clients
        for websocket in disconnected:
            self.connections.discard(websocket)
            self.connection_stats["active_connections"] -= 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics"""
        return self.connection_stats.copy()


class AlertProcessor:
    """Alert processing and enrichment"""
    
    def __init__(self):
        self.enabled = os.getenv("ALERT_PROCESSOR_ENABLED", "true").lower() == "true"
        
        # Alert enrichment rules
        self.enrichment_rules = self._load_enrichment_rules()
        
        # Alert deduplication
        self.alert_cache = {}
        self.deduplication_window = timedelta(minutes=5)
        
        # Processing statistics
        self.processing_stats = {
            "alerts_processed": 0,
            "alerts_enriched": 0,
            "alerts_deduplicated": 0,
            "alerts_filtered": 0
        }
        
        logger.info("Alert processor initialized", enabled=self.enabled)
    
    def _load_enrichment_rules(self) -> List[Callable]:
        """Load alert enrichment rules"""
        rules = []
        
        # Geographic enrichment
        def add_geographic_context(alert: LiveAlert) -> LiveAlert:
            if alert.ip_address:
                # Mock geographic lookup
                alert.metadata["geo_context"] = {
                    "country": "Unknown",
                    "city": "Unknown",
                    "is_suspicious": False
                }
            return alert
        
        # User context enrichment
        def add_user_context(alert: LiveAlert) -> LiveAlert:
            if alert.user_id:
                # Mock user context lookup
                alert.metadata["user_context"] = {
                    "is_admin": False,
                    "last_login": datetime.utcnow() - timedelta(hours=2),
                    "risk_score": 0.3
                }
            return alert
        
        # Threat intelligence enrichment
        def add_threat_intel(alert: LiveAlert) -> LiveAlert:
            if alert.ip_address:
                # Mock threat intelligence lookup
                alert.metadata["threat_intel"] = {
                    "ip_reputation": "neutral",
                    "malicious_indicators": [],
                    "confidence": 0.5
                }
            return alert
        
        rules.extend([add_geographic_context, add_user_context, add_threat_intel])
        return rules
    
    async def process_alert(self, alert: LiveAlert) -> Optional[LiveAlert]:
        """Process and enrich alert"""
        if not self.enabled:
            return alert
        
        self.processing_stats["alerts_processed"] += 1
        
        # Check for deduplication
        if self._is_duplicate(alert):
            self.processing_stats["alerts_deduplicated"] += 1
            return None
        
        # Apply enrichment rules
        for rule in self.enrichment_rules:
            try:
                alert = rule(alert)
            except Exception as e:
                logger.error(f"Alert enrichment rule failed: {rule.__name__}", error=str(e))
        
        self.processing_stats["alerts_enriched"] += 1
        
        # Add processing metadata
        alert.metadata["processed_at"] = datetime.utcnow().isoformat()
        alert.metadata["processing_version"] = "1.0"
        
        return alert
    
    def _is_duplicate(self, alert: LiveAlert) -> bool:
        """Check if alert is duplicate"""
        # Create deduplication key
        key_parts = [
            alert.category.value,
            alert.source,
            alert.ip_address or "",
            alert.user_id or "",
            alert.title
        ]
        dedup_key = hashlib.md5("|".join(key_parts).encode()).hexdigest()
        
        # Check cache
        if dedup_key in self.alert_cache:
            last_seen = self.alert_cache[dedup_key]
            if datetime.utcnow() - last_seen < self.deduplication_window:
                return True
        
        # Update cache
        self.alert_cache[dedup_key] = datetime.utcnow()
        
        # Clean old entries
        self._cleanup_cache()
        
        return False
    
    def _cleanup_cache(self):
        """Clean old deduplication cache entries"""
        cutoff = datetime.utcnow() - self.deduplication_window
        expired_keys = [
            key for key, timestamp in self.alert_cache.items()
            if timestamp < cutoff
        ]
        
        for key in expired_keys:
            del self.alert_cache[key]
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            "enabled": self.enabled,
            **self.processing_stats,
            "cache_size": len(self.alert_cache),
            "enrichment_rules": len(self.enrichment_rules)
        }


class LiveAlertSystem:
    """Main live alert system"""
    
    def __init__(self):
        self.enabled = os.getenv("LIVE_ALERTS_ENABLED", "true").lower() == "true"
        
        # Core components
        self.alert_queue = AlertQueue(max_size=int(os.getenv("ALERT_QUEUE_SIZE", "10000")))
        self.websocket_manager = WebSocketManager()
        self.alert_processor = AlertProcessor()
        
        # Alert storage
        self.active_alerts = {}
        self.alert_history = deque(maxlen=10000)
        
        # Alert processing workers
        self.workers = []
        self.max_workers = int(os.getenv("ALERT_WORKERS", "4"))
        
        # Alert filtering
        self.alert_filters = []
        self._load_alert_filters()
        
        # System statistics
        self.system_stats = {
            "alerts_received": 0,
            "alerts_processed": 0,
            "alerts_broadcast": 0,
            "start_time": datetime.utcnow()
        }
        
        logger.info("Live alert system initialized", enabled=self.enabled)
    
    def _load_alert_filters(self):
        """Load alert filtering rules"""
        # Example filter: suppress low-priority system alerts during high load
        def suppress_low_priority_system(alert: LiveAlert) -> bool:
            return not (
                alert.priority == AlertPriority.LOW and 
                alert.category == AlertCategory.SYSTEM and
                self.alert_queue.size() > 1000
            )
        
        self.alert_filters.append(suppress_low_priority_system)
    
    async def start(self):
        """Start live alert system"""
        if not self.enabled:
            return
        
        # Start alert processing workers
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._alert_worker(f"alert-worker-{i}"))
            self.workers.append(worker)
        
        # Start WebSocket server
        websocket_server = asyncio.create_task(self._start_websocket_server())
        
        logger.info(f"Live alert system started with {self.max_workers} workers")
        
        return websocket_server
    
    async def stop(self):
        """Stop live alert system"""
        if not self.enabled:
            return
        
        # Cancel workers
        for worker in self.workers:
            worker.cancel()
        
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        
        logger.info("Live alert system stopped")
    
    async def create_alert(self, 
                          priority: AlertPriority,
                          category: AlertCategory,
                          title: str,
                          description: str,
                          source: str = "",
                          details: Dict[str, Any] = None,
                          correlation_id: str = None,
                          user_id: str = None,
                          ip_address: str = None,
                          tags: List[str] = None) -> Optional[str]:
        """Create new alert"""
        if not self.enabled:
            return None
        
        alert = LiveAlert(
            priority=priority,
            category=category,
            title=title,
            description=description,
            source=source,
            details=details or {},
            correlation_id=correlation_id,
            user_id=user_id,
            ip_address=ip_address,
            tags=tags or []
        )
        
        # Apply filters
        for filter_func in self.alert_filters:
            if not filter_func(alert):
                self.system_stats["alerts_received"] += 1
                return None
        
        # Add to queue
        success = await self.alert_queue.put(alert)
        if success:
            self.system_stats["alerts_received"] += 1
            return alert.id
        
        return None
    
    async def _alert_worker(self, worker_name: str):
        """Alert processing worker"""
        logger.info(f"{worker_name} started")
        
        while True:
            try:
                # Get alert from queue
                alert = await self.alert_queue.get()
                
                # Process alert
                processed_alert = await self.alert_processor.process_alert(alert)
                
                if processed_alert:
                    # Store alert
                    self.active_alerts[processed_alert.id] = processed_alert
                    self.alert_history.append(processed_alert)
                    
                    # Broadcast to WebSocket clients
                    await self._broadcast_alert(processed_alert)
                    
                    # Send to SIEM
                    await self._send_to_siem(processed_alert)
                    
                    self.system_stats["alerts_processed"] += 1
                    self.system_stats["alerts_broadcast"] += 1
                
                self.alert_queue.task_done()
                
            except Exception as e:
                logger.error(f"{worker_name} error", error=str(e))
    
    async def _broadcast_alert(self, alert: LiveAlert):
        """Broadcast alert to WebSocket clients"""
        broadcast_data = {
            "type": "alert",
            "timestamp": datetime.utcnow().isoformat(),
            "alert": alert.to_dict(),
            "siem_payload": alert.to_siem_payload()
        }
        
        await self.websocket_manager.broadcast(broadcast_data)
    
    async def _send_to_siem(self, alert: LiveAlert):
        """Send alert to SIEM system"""
        try:
            # Mock SIEM integration - in production, this would send to actual SIEM
            siem_payload = alert.to_siem_payload()
            
            # Log SIEM payload (in production, send to SIEM endpoint)
            log_security_event(
                "siem_alert",
                {
                    "alert_id": alert.id,
                    "priority": alert.priority.value,
                    "category": alert.category.value,
                    "siem_payload": siem_payload
                }
            )
            
        except Exception as e:
            logger.error("SIEM integration failed", error=str(e))
    
    async def _start_websocket_server(self):
        """Start WebSocket server for live alerts"""
        host = os.getenv("WEBSOCKET_HOST", "0.0.0.0")
        port = int(os.getenv("WEBSOCKET_PORT", "8765"))
        
        async def handle_websocket(websocket, path):
            await self.websocket_manager.register(websocket)
            
            try:
                # Send initial alert summary
                await self.websocket_manager.send_to_client(websocket, {
                    "type": "initial_state",
                    "timestamp": datetime.utcnow().isoformat(),
                    "active_alerts": len(self.active_alerts),
                    "system_stats": self.get_system_stats()
                })
                
                # Keep connection alive
                await websocket.wait_closed()
                
            except websockets.exceptions.ConnectionClosed:
                pass
            finally:
                await self.websocket_manager.unregister(websocket)
        
        # Start WebSocket server
        server = await websockets.serve(handle_websocket, host, port)
        logger.info(f"WebSocket server started on {host}:{port}")
        
        await server.wait_closed()
    
    async def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge alert"""
        if alert_id not in self.active_alerts:
            return False
        
        alert = self.active_alerts[alert_id]
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user_id
        alert.acknowledged_at = datetime.utcnow()
        
        # Broadcast update
        await self._broadcast_alert(alert)
        
        # Log acknowledgment
        log_audit_event(
            "alert_acknowledged",
            user=user_id,
            resource=f"alert:{alert_id}",
            result="success"
        )
        
        return True
    
    async def resolve_alert(self, alert_id: str, user_id: str, resolution: str) -> bool:
        """Resolve alert"""
        if alert_id not in self.active_alerts:
            return False
        
        alert = self.active_alerts[alert_id]
        alert.status = AlertStatus.RESOLVED
        alert.resolved_by = user_id
        alert.resolved_at = datetime.utcnow()
        alert.resolution = resolution
        
        # Move to history
        self.alert_history.append(alert)
        del self.active_alerts[alert_id]
        
        # Broadcast update
        await self._broadcast_alert(alert)
        
        # Log resolution
        log_audit_event(
            "alert_resolved",
            user=user_id,
            resource=f"alert:{alert_id}",
            result="success",
            details={"resolution": resolution}
        )
        
        return True
    
    def get_active_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get active alerts"""
        alerts = list(self.active_alerts.values())[:limit]
        return [alert.to_dict() for alert in alerts]
    
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alert history"""
        alerts = list(self.alert_history)[-limit:]
        return [alert.to_dict() for alert in alerts]
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        uptime = datetime.utcnow() - self.system_stats["start_time"]
        
        return {
            "enabled": self.enabled,
            "uptime_seconds": uptime.total_seconds(),
            "active_alerts": len(self.active_alerts),
            "total_alerts": len(self.alert_history),
            "websocket_connections": self.websocket_manager.get_stats(),
            "queue_stats": self.alert_queue.get_stats(),
            "processing_stats": self.alert_processor.get_processing_stats(),
            **self.system_stats
        }


# Global live alert system instance
live_alert_system = LiveAlertSystem()


async def start_live_alert_system():
    """Start live alert system"""
    return await live_alert_system.start()


async def stop_live_alert_system():
    """Stop live alert system"""
    await live_alert_system.stop()


async def create_alert(priority: AlertPriority,
                     category: AlertCategory,
                     title: str,
                     description: str,
                     **kwargs) -> Optional[str]:
    """Create new alert"""
    return await live_alert_system.create_alert(
        priority, category, title, description, **kwargs
    )


async def acknowledge_alert(alert_id: str, user_id: str) -> bool:
    """Acknowledge alert"""
    return await live_alert_system.acknowledge_alert(alert_id, user_id)


async def resolve_alert(alert_id: str, user_id: str, resolution: str) -> bool:
    """Resolve alert"""
    return await live_alert_system.resolve_alert(alert_id, user_id, resolution)


def get_live_alert_stats() -> Dict[str, Any]:
    """Get live alert system statistics"""
    return live_alert_system.get_system_stats()
