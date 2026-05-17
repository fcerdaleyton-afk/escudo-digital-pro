"""
MARY V5 SHIELD CORE - Live Threat Stream
Real-time websocket stream with attack telemetry and live threat feed
"""

import os
import json
import time
import asyncio
import websockets
from typing import Dict, List, Optional, Any, Set, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
import weakref
import uuid

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger
from app.core.security_settings import get_security_settings


class ThreatSeverity(Enum):
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(Enum):
    """Threat categories"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    RATE_LIMITING = "rate_limiting"
    DDOS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    INJECTION = "injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    ANOMALY = "anomaly"
    SYSTEM = "system"
    NETWORK = "network"


class StreamEventType(Enum):
    """Stream event types"""
    THREAT_DETECTED = "threat_detected"
    ATTACK_TELEMETRY = "attack_telemetry"
    SYSTEM_STATUS = "system_status"
    METRICS_UPDATE = "metrics_update"
    ALERT_BROADCAST = "alert_broadcast"
    INCIDENT_CREATED = "incident_created"
    THREAT_INTEL_UPDATE = "threat_intel_update"


@dataclass
class ThreatEvent:
    """Threat event data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    category: ThreatCategory = ThreatCategory.ANOMALY
    title: str = ""
    description: str = ""
    source_ip: Optional[str] = None
    target: Optional[str] = None
    attack_vector: Optional[str] = None
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    telemetry: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['severity'] = self.severity.value
        data['category'] = self.category.value
        return data


@dataclass
class AttackTelemetry:
    """Attack telemetry data"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    attack_type: str = ""
    source_ip: str = ""
    target_endpoint: str = ""
    request_count: int = 0
    failure_count: int = 0
    success_count: int = 0
    avg_response_time: float = 0.0
    payload_sizes: List[int] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    geo_location: Optional[str] = None
    attack_pattern: str = ""
    duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class StreamEvent:
    """Stream event wrapper"""
    event_type: StreamEventType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['event_type'] = self.event_type.value
        return data


class EventBuffer:
    """Rolling event buffer with configurable size"""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.buffer: deque = deque(maxlen=max_size)
        self._lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "total_events": 0,
            "events_by_type": defaultdict(int),
            "events_by_severity": defaultdict(int),
            "buffer_utilization": 0.0
        }
    
    async def add_event(self, event: StreamEvent):
        """Add event to buffer"""
        async with self._lock:
            self.buffer.append(event)
            self.stats["total_events"] += 1
            self.stats["events_by_type"][event.event_type.value] += 1
            
            if hasattr(event.data, 'severity'):
                self.stats["events_by_severity"][event.data.severity.value] += 1
            
            self.stats["buffer_utilization"] = len(self.buffer) / self.max_size
    
    async def get_recent_events(self, limit: int = 100, event_type: Optional[StreamEventType] = None) -> List[StreamEvent]:
        """Get recent events from buffer"""
        async with self._lock:
            events = list(self.buffer)
            
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            
            # Return most recent events
            return events[-limit:] if len(events) > limit else events
    
    async def get_events_by_time_range(self, start_time: datetime, end_time: datetime) -> List[StreamEvent]:
        """Get events within time range"""
        async with self._lock:
            return [
                event for event in self.buffer
                if start_time <= event.timestamp <= end_time
            ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get buffer statistics"""
        return {
            "max_size": self.max_size,
            "current_size": len(self.buffer),
            "utilization": self.stats["buffer_utilization"],
            "total_events": self.stats["total_events"],
            "events_by_type": dict(self.stats["events_by_type"]),
            "events_by_severity": dict(self.stats["events_by_severity"])
        }


class WebSocketManager:
    """WebSocket connection manager for threat streaming"""
    
    def __init__(self):
        self.connections: Set[websockets.WebSocketServerProtocol] = weakref.WeakSet()
        self.connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_failed": 0,
            "connections_by_type": defaultdict(int)
        }
        self._lock = asyncio.Lock()
        
        self.logger = get_structured_logger("websocket_manager")
    
    async def register(self, websocket: websockets.WebSocketServerProtocol, connection_type: str = "default"):
        """Register new WebSocket connection"""
        await self._lock.acquire()
        try:
            self.connections.add(websocket)
            self.connection_stats["total_connections"] += 1
            self.connection_stats["active_connections"] += 1
            self.connection_stats["connections_by_type"][connection_type] += 1
            
            self.logger.info("WebSocket client connected", 
                           total_connections=self.connection_stats["active_connections"],
                           connection_type=connection_type)
            
            # Send welcome message
            await self.send_to_client(websocket, {
                "type": "connection_established",
                "timestamp": datetime.utcnow().isoformat(),
                "message": "Connected to MARY V5 threat stream",
                "connection_id": str(id(websocket)),
                "stream_version": "2.0.0"
            })
            
        finally:
            await self._lock.release()
    
    async def unregister(self, websocket: websockets.WebSocketServerProtocol, connection_type: str = "default"):
        """Unregister WebSocket connection"""
        await self._lock.acquire()
        try:
            self.connections.discard(websocket)
            self.connection_stats["active_connections"] -= 1
            
            self.logger.info("WebSocket client disconnected", 
                           active_connections=self.connection_stats["active_connections"],
                           connection_type=connection_type)
        finally:
            await self._lock.release()
    
    async def send_to_client(self, websocket: websockets.WebSocketServerProtocol, message: Dict[str, Any]):
        """Send message to specific client"""
        try:
            await websocket.send(json.dumps(message, default=str))
            self.connection_stats["messages_sent"] += 1
        except Exception as e:
            self.connection_stats["messages_failed"] += 1
            self.logger.error("Failed to send WebSocket message", error=str(e))
    
    async def broadcast(self, message: Dict[str, Any], connection_type: str = "all"):
        """Broadcast message to all connected clients"""
        await self._lock.acquire()
        try:
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
        
        finally:
            await self._lock.release()
    
    async def broadcast_threat_event(self, threat_event: ThreatEvent):
        """Broadcast threat event to all clients"""
        message = {
            "type": "threat_event",
            "timestamp": datetime.utcnow().isoformat(),
            "threat": threat_event.to_dict()
        }
        await self.broadcast(message)
    
    async def broadcast_attack_telemetry(self, telemetry: AttackTelemetry):
        """Broadcast attack telemetry to all clients"""
        message = {
            "type": "attack_telemetry",
            "timestamp": datetime.utcnow().isoformat(),
            "telemetry": telemetry.to_dict()
        }
        await self.broadcast(message)
    
    async def broadcast_system_status(self, status: Dict[str, Any]):
        """Broadcast system status to all clients"""
        message = {
            "type": "system_status",
            "timestamp": datetime.utcnow().isoformat(),
            "status": status
        }
        await self.broadcast(message)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics"""
        return {
            "active_connections": self.connection_stats["active_connections"],
            "total_connections": self.connection_stats["total_connections"],
            "messages_sent": self.connection_stats["messages_sent"],
            "messages_failed": self.connection_stats["messages_failed"],
            "connections_by_type": dict(self.connection_stats["connections_by_type"])
        }


class ThreatStreamProcessor:
    """Async threat stream processor"""
    
    def __init__(self):
        self.enabled = os.getenv("THREAT_STREAM_PROCESSOR_ENABLED", "true").lower() == "true"
        
        # Processing queue
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.workers = []
        self.max_workers = int(os.getenv("THREAT_STREAM_WORKERS", "4"))
        
        # Processing statistics
        self.processing_stats = {
            "events_processed": 0,
            "events_failed": 0,
            "processing_time_avg": 0.0,
            "events_by_type": defaultdict(int)
        }
        
        self.logger = get_structured_logger("threat_stream_processor")
        
        # Event handlers
        self.event_handlers: Dict[StreamEventType, List[Callable]] = defaultdict(list)
        
        self.logger.info("Threat stream processor initialized", enabled=self.enabled)
    
    async def start(self):
        """Start threat stream processor"""
        if not self.enabled:
            return
        
        # Start worker coroutines
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._worker(f"threat-worker-{i}"))
            self.workers.append(worker)
        
        self.logger.info(f"Threat stream processor started with {self.max_workers} workers")
    
    async def stop(self):
        """Stop threat stream processor"""
        if not self.enabled:
            return
        
        # Cancel workers
        for worker in self.workers:
            worker.cancel()
        
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        
        self.logger.info("Threat stream processor stopped")
    
    async def submit_event(self, event: StreamEvent):
        """Submit event for processing"""
        if not self.enabled:
            return
        
        try:
            await self.event_queue.put(event)
        except asyncio.QueueFull:
            self.processing_stats["events_failed"] += 1
            self.logger.warning("Threat stream queue full, dropping event")
    
    def register_handler(self, event_type: StreamEventType, handler: Callable):
        """Register event handler"""
        self.event_handlers[event_type].append(handler)
    
    async def _worker(self, worker_name: str):
        """Event processing worker"""
        self.logger.info(f"{worker_name} started")
        
        while True:
            try:
                # Get event from queue
                event = await asyncio.wait_for(
                    self.event_queue.get(),
                    timeout=1.0
                )
                
                # Process event
                await self._process_event(event)
                
                self.event_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.processing_stats["events_failed"] += 1
                self.logger.error(f"{worker_name} error", error=str(e))
    
    async def _process_event(self, event: StreamEvent):
        """Process individual event"""
        start_time = time.time()
        
        try:
            # Update statistics
            self.processing_stats["events_processed"] += 1
            self.processing_stats["events_by_type"][event.event_type.value] += 1
            
            # Call registered handlers
            handlers = self.event_handlers.get(event.event_type, [])
            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    self.logger.error(f"Event handler error: {handler.__name__}", error=str(e))
            
            # Update processing time
            processing_time = time.time() - start_time
            total_events = self.processing_stats["events_processed"]
            self.processing_stats["processing_time_avg"] = (
                (self.processing_stats["processing_time_avg"] * (total_events - 1) + processing_time) / total_events
            )
            
        except Exception as e:
            self.processing_stats["events_failed"] += 1
            self.logger.error("Event processing error", error=str(e))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            "enabled": self.enabled,
            "queue_size": self.event_queue.qsize(),
            "workers": len(self.workers),
            "max_workers": self.max_workers,
            **self.processing_stats
        }


class LiveThreatStream:
    """Main live threat stream system"""
    
    def __init__(self):
        self.enabled = os.getenv("LIVE_THREAT_STREAM_ENABLED", "true").lower() == "true"
        
        # Core components
        self.websocket_manager = WebSocketManager()
        self.event_buffer = EventBuffer(max_size=10000)
        self.stream_processor = ThreatStreamProcessor()
        
        # Stream configuration
        self.websocket_host = os.getenv("WEBSOCKET_HOST", "0.0.0.0")
        self.websocket_port = int(os.getenv("WEBSOCKET_PORT", "8765"))
        self.max_connections = int(os.getenv("WEBSOCKET_MAX_CONNECTIONS", "1000"))
        
        # Stream statistics
        self.stream_stats = {
            "threats_detected": 0,
            "attacks_detected": 0,
            "telemetry_points": 0,
            "alerts_broadcast": 0,
            "start_time": datetime.utcnow()
        }
        
        # Background tasks
        self.websocket_server = None
        self.cleanup_task = None
        
        self.logger = get_structured_logger("live_threat_stream")
        
        # Register event handlers
        self._register_event_handlers()
        
        self.logger.info("Live threat stream initialized", enabled=self.enabled)
    
    def _register_event_handlers(self):
        """Register event handlers"""
        self.stream_processor.register_handler(StreamEventType.THREAT_DETECTED, self._handle_threat_detected)
        self.stream_processor.register_handler(StreamEventType.ATTACK_TELEMETRY, self._handle_attack_telemetry)
        self.stream_processor.register_handler(StreamEventType.SYSTEM_STATUS, self._handle_system_status)
    
    async def start(self):
        """Start live threat stream"""
        if not self.enabled:
            return
        
        # Start stream processor
        await self.stream_processor.start()
        
        # Start WebSocket server
        self.websocket_server = asyncio.create_task(self._start_websocket_server())
        
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_task())
        
        self.logger.info("Live threat stream started")
    
    async def stop(self):
        """Stop live threat stream"""
        if not self.enabled:
            return
        
        # Stop stream processor
        await self.stream_processor.stop()
        
        # Cancel background tasks
        if self.websocket_server:
            self.websocket_server.cancel()
            try:
                await self.websocket_server
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Live threat stream stopped")
    
    async def _start_websocket_server(self):
        """Start WebSocket server for threat streaming"""
        async def handle_websocket(websocket, path):
            connection_type = "threat_stream"
            if path.startswith("/admin"):
                connection_type = "admin"
            elif path.startswith("/telemetry"):
                connection_type = "telemetry"
            
            await self.websocket_manager.register(websocket, connection_type)
            
            try:
                # Send initial state
                await self._send_initial_state(websocket)
                
                # Keep connection alive and handle client messages
                async for message in websocket:
                    try:
                        await self._handle_client_message(websocket, message)
                    except Exception as e:
                        self.logger.error("Client message handling error", error=str(e))
                
            except websockets.exceptions.ConnectionClosed:
                pass
            except Exception as e:
                self.logger.error("WebSocket connection error", error=str(e))
            finally:
                await self.websocket_manager.unregister(websocket, connection_type)
        
        # Start WebSocket server
        server = await websockets.serve(
            handle_websocket,
            self.websocket_host,
            self.websocket_port,
            max_size=10**7,  # 10MB max message size
            ping_interval=20,
            ping_timeout=10
        )
        
        self.logger.info(f"WebSocket server started on {self.websocket_host}:{self.websocket_port}")
        
        await server.wait_closed()
    
    async def _send_initial_state(self, websocket: websockets.WebSocketServerProtocol):
        """Send initial state to new client"""
        initial_state = {
            "type": "initial_state",
            "timestamp": datetime.utcnow().isoformat(),
            "stream_info": {
                "version": "2.0.0",
                "capabilities": [
                    "threat_events",
                    "attack_telemetry",
                    "system_status",
                    "real_time_alerts"
                ]
            },
            "recent_threats": await self._get_recent_threats(10),
            "stream_statistics": self.get_stream_statistics()
        }
        
        await self.websocket_manager.send_to_client(websocket, initial_state)
    
    async def _handle_client_message(self, websocket: websockets.WebSocketServerProtocol, message: str):
        """Handle client message"""
        try:
            data = json.loads(message)
            message_type = data.get("type")
            
            if message_type == "subscribe":
                # Handle subscription requests
                await self._handle_subscription(websocket, data)
            elif message_type == "get_history":
                # Handle history requests
                await self._handle_history_request(websocket, data)
            elif message_type == "ping":
                # Handle ping
                await self.websocket_manager.send_to_client(websocket, {
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                })
            
        except json.JSONDecodeError:
            self.logger.warning("Invalid JSON message from client")
        except Exception as e:
            self.logger.error("Client message handling error", error=str(e))
    
    async def _handle_subscription(self, websocket: websockets.WebSocketServerProtocol, data: Dict[str, Any]):
        """Handle client subscription"""
        subscription_type = data.get("subscription", "all")
        
        response = {
            "type": "subscription_confirmed",
            "timestamp": datetime.utcnow().isoformat(),
            "subscription": subscription_type
        }
        
        await self.websocket_manager.send_to_client(websocket, response)
    
    async def _handle_history_request(self, websocket: websockets.WebSocketServerProtocol, data: Dict[str, Any]):
        """Handle history request"""
        limit = data.get("limit", 50)
        event_type = data.get("event_type")
        
        if event_type:
            stream_event_type = StreamEventType(event_type)
            events = await self.event_buffer.get_recent_events(limit, stream_event_type)
        else:
            events = await self.event_buffer.get_recent_events(limit)
        
        response = {
            "type": "history_response",
            "timestamp": datetime.utcnow().isoformat(),
            "events": [event.to_dict() for event in events]
        }
        
        await self.websocket_manager.send_to_client(websocket, response)
    
    async def _get_recent_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent threat events"""
        threat_events = await self.event_buffer.get_recent_events(
            limit, StreamEventType.THREAT_DETECTED
        )
        
        return [
            event.data.to_dict() 
            for event in threat_events 
            if hasattr(event, 'data') and isinstance(event.data, ThreatEvent)
        ]
    
    async def _handle_threat_detected(self, event: StreamEvent):
        """Handle threat detected event"""
        if hasattr(event, 'data') and isinstance(event.data, ThreatEvent):
            self.stream_stats["threats_detected"] += 1
            
            # Add to buffer
            await self.event_buffer.add_event(event)
            
            # Broadcast to WebSocket clients
            await self.websocket_manager.broadcast_threat_event(event.data)
    
    async def _handle_attack_telemetry(self, event: StreamEvent):
        """Handle attack telemetry event"""
        if hasattr(event, 'data') and isinstance(event.data, AttackTelemetry):
            self.stream_stats["attacks_detected"] += 1
            self.stream_stats["telemetry_points"] += 1
            
            # Add to buffer
            await self.event_buffer.add_event(event)
            
            # Broadcast to telemetry clients
            message = {
                "type": "attack_telemetry",
                "timestamp": datetime.utcnow().isoformat(),
                "telemetry": event.data.to_dict()
            }
            await self.websocket_manager.broadcast(message, "telemetry")
    
    async def _handle_system_status(self, event: StreamEvent):
        """Handle system status event"""
        # Add to buffer
        await self.event_buffer.add_event(event)
            
        # Broadcast to admin clients
        message = {
            "type": "system_status",
            "timestamp": datetime.utcnow().isoformat(),
            "status": event.data
        }
        await self.websocket_manager.broadcast(message, "admin")
    
    async def publish_threat_event(self, threat_event: ThreatEvent):
        """Publish threat event to stream"""
        if not self.enabled:
            return
        
        stream_event = StreamEvent(
            event_type=StreamEventType.THREAT_DETECTED,
            data=threat_event
        )
        
        await self.stream_processor.submit_event(stream_event)
    
    async def publish_attack_telemetry(self, telemetry: AttackTelemetry):
        """Publish attack telemetry to stream"""
        if not self.enabled:
            return
        
        stream_event = StreamEvent(
            event_type=StreamEventType.ATTACK_TELEMETRY,
            data=telemetry
        )
        
        await self.stream_processor.submit_event(stream_event)
    
    async def publish_system_status(self, status: Dict[str, Any]):
        """Publish system status to stream"""
        if not self.enabled:
            return
        
        stream_event = StreamEvent(
            event_type=StreamEventType.SYSTEM_STATUS,
            data=status
        )
        
        await self.stream_processor.submit_event(stream_event)
    
    async def _cleanup_task(self):
        """Periodic cleanup task"""
        while True:
            try:
                # Clean up old events (older than 24 hours)
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                old_events = await self.event_buffer.get_events_by_time_range(
                    datetime.min, cutoff_time
                )
                
                if old_events:
                    self.logger.info(f"Cleaned up {len(old_events)} old events")
                
                # Wait for next cleanup
                await asyncio.sleep(3600)  # 1 hour
                
            except Exception as e:
                self.logger.error("Cleanup task error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error
    
    def get_stream_statistics(self) -> Dict[str, Any]:
        """Get comprehensive stream statistics"""
        uptime = datetime.utcnow() - self.stream_stats["start_time"]
        
        return {
            "enabled": self.enabled,
            "uptime_seconds": uptime.total_seconds(),
            "websocket": self.websocket_manager.get_statistics(),
            "event_buffer": self.event_buffer.get_statistics(),
            "stream_processor": self.stream_processor.get_statistics(),
            "stream_stats": self.stream_stats,
            "configuration": {
                "websocket_host": self.websocket_host,
                "websocket_port": self.websocket_port,
                "max_connections": self.max_connections
            }
        }


# Global live threat stream instance
live_threat_stream = LiveThreatStream()


async def start_live_threat_stream():
    """Start live threat stream"""
    await live_threat_stream.start()


async def stop_live_threat_stream():
    """Stop live threat stream"""
    await live_threat_stream.stop()


async def publish_threat_event(threat_event: ThreatEvent):
    """Publish threat event"""
    await live_threat_stream.publish_threat_event(threat_event)


async def publish_attack_telemetry(telemetry: AttackTelemetry):
    """Publish attack telemetry"""
    await live_threat_stream.publish_attack_telemetry(telemetry)


async def publish_system_status(status: Dict[str, Any]):
    """Publish system status"""
    await live_threat_stream.publish_system_status(status)


def get_threat_stream_statistics() -> Dict[str, Any]:
    """Get threat stream statistics"""
    return live_threat_stream.get_stream_statistics()
