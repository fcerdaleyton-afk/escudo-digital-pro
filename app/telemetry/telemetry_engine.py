"""
MARY V5 SHIELD CORE v5.0 Enterprise - Telemetry Engine
Comprehensive telemetry engine with Sysmon integration and event forwarding
"""

import os
import sys
import asyncio
import logging
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
def setup_logging():
    """Setup logging with proper path handling"""
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, 'telemetry_engine.log')),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)

# Import telemetry components
try:
    from .sysmon_integration import sysmon_integration, add_sysmon_callback
    from alerting import create_alert
except ImportError as e:
    logger.error(f"Failed to import telemetry components: {e}")
    sys.exit(1)


class EventType(Enum):
    """Telemetry event types"""
    SYSMON_EVENT = "sysmon_event"
    INCIDENT = "incident"
    AUDIT_LOG = "audit_log"
    THREAT_DETECTION = "threat_detection"
    WEBSOCKET_TELEMETRY = "websocket_telemetry"


class EventPriority(Enum):
    """Event priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TelemetryEvent:
    """Telemetry event data structure"""
    event_id: str
    timestamp: datetime
    event_type: EventType
    priority: EventPriority
    source: str
    title: str
    description: str
    data: Dict[str, Any]
    severity: str
    tags: List[str] = None
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'priority': self.priority.value,
            'source': self.source,
            'title': self.title,
            'description': self.description,
            'data': self.data,
            'severity': self.severity,
            'tags': self.tags or [],
            'correlation_id': self.correlation_id
        }


class TelemetryEngine:
    """Comprehensive telemetry engine with event forwarding"""
    
    def __init__(self):
        """Initialize telemetry engine"""
        self.is_running = False
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=50000)
        self.processed_events: deque = deque(maxlen=100000)
        self.websocket_clients: List[Callable] = []
        self.incident_callbacks: List[Callable] = []
        self.audit_callbacks: List[Callable] = []
        self.threat_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'events_by_type': defaultdict(int),
            'events_by_priority': defaultdict(int),
            'events_by_severity': defaultdict(int),
            'websocket_clients': 0,
            'incidents_generated': 0,
            'audit_logs_generated': 0,
            'threat_detections_generated': 0
        }
        
        # Configuration
        self.config = {
            'max_queue_size': 50000,
            'max_event_history': 100000,
            'websocket_enabled': True,
            'incident_generation_enabled': True,
            'audit_logging_enabled': True,
            'threat_detection_enabled': True,
            'event_retention_hours': 168,  # 7 days
            'batch_processing_size': 100,
            'processing_interval': 5,  # seconds
            'alert_threshold': EventPriority.HIGH
        }
        
        logger.info("Telemetry engine initialized")
    
    async def start(self):
        """Start telemetry engine"""
        try:
            logger.info("Starting telemetry engine")
            
            self.is_running = True
            
            # Setup Sysmon integration
            add_sysmon_callback(self._handle_sysmon_event)
            
            # Start background tasks
            asyncio.create_task(self._process_event_queue())
            asyncio.create_task(self._cleanup_old_events())
            asyncio.create_task(self._generate_statistics_report())
            
            logger.info("Telemetry engine started successfully")
            
        except Exception as e:
            logger.error(f"Error starting telemetry engine: {e}")
            raise
    
    async def stop(self):
        """Stop telemetry engine"""
        try:
            logger.info("Stopping telemetry engine")
            
            self.is_running = False
            
            logger.info("Telemetry engine stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping telemetry engine: {e}")
    
    def add_websocket_client(self, callback: Callable):
        """Add WebSocket client"""
        self.websocket_clients.append(callback)
        self.stats['websocket_clients'] = len(self.websocket_clients)
        logger.info(f"WebSocket client added (total: {len(self.websocket_clients)})")
    
    def remove_websocket_client(self, callback: Callable):
        """Remove WebSocket client"""
        if callback in self.websocket_clients:
            self.websocket_clients.remove(callback)
            self.stats['websocket_clients'] = len(self.websocket_clients)
            logger.info(f"WebSocket client removed (total: {len(self.websocket_clients)})")
    
    def add_incident_callback(self, callback: Callable):
        """Add incident callback"""
        self.incident_callbacks.append(callback)
        logger.info(f"Incident callback added (total: {len(self.incident_callbacks)})")
    
    def add_audit_callback(self, callback: Callable):
        """Add audit callback"""
        self.audit_callbacks.append(callback)
        logger.info(f"Audit callback added (total: {len(self.audit_callbacks)})")
    
    def add_threat_callback(self, callback: Callable):
        """Add threat detection callback"""
        self.threat_callbacks.append(callback)
        logger.info(f"Threat detection callback added (total: {len(self.threat_callbacks)})")
    
    async def _handle_sysmon_event(self, sysmon_data: Dict[str, Any]):
        """Handle Sysmon event"""
        try:
            # Convert to telemetry event
            telemetry_event = TelemetryEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.fromisoformat(sysmon_data['data']['timestamp']),
                event_type=EventType.SYSMON_EVENT,
                priority=self._determine_priority(sysmon_data['data']),
                source="sysmon",
                title=f"Sysmon {sysmon_data['data']['event_type']}",
                description=self._generate_description(sysmon_data['data']),
                data=sysmon_data['data'],
                severity=sysmon_data['data']['severity'],
                tags=self._generate_tags(sysmon_data['data']),
                correlation_id=self._generate_correlation_id(sysmon_data['data'])
            )
            
            # Add to queue
            await self.event_queue.put(telemetry_event)
            
            logger.debug(f"Sysmon event queued: {telemetry_event.event_type.value}")
            
        except Exception as e:
            logger.error(f"Error handling Sysmon event: {e}")
    
    def _determine_priority(self, event_data: Dict[str, Any]) -> EventPriority:
        """Determine event priority"""
        severity = event_data.get('severity', 'low')
        threat_indicators = event_data.get('threat_indicators', [])
        
        # Critical indicators
        if severity == 'critical':
            return EventPriority.CRITICAL
        
        # High priority indicators
        if severity == 'high' or len(threat_indicators) >= 2:
            return EventPriority.HIGH
        
        # Medium priority indicators
        if severity == 'medium' or len(threat_indicators) == 1:
            return EventPriority.MEDIUM
        
        return EventPriority.LOW
    
    def _generate_description(self, event_data: Dict[str, Any]) -> str:
        """Generate event description"""
        event_type = event_data.get('event_type', 'unknown')
        process_name = event_data.get('process_name', 'unknown')
        threat_indicators = event_data.get('threat_indicators', [])
        
        descriptions = {
            1: f"Process created: {process_name}",
            3: f"Network connection from: {process_name}",
            2: f"File created by: {process_name}",
            5: f"Process terminated: {process_name}",
            7: f"Image loaded by: {process_name}",
            10: f"Process access: {process_name}"
        }
        
        base_desc = descriptions.get(event_type, f"Sysmon event: {event_type}")
        
        if threat_indicators:
            base_desc += f" (Threats: {', '.join(threat_indicators)})"
        
        return base_desc
    
    def _generate_tags(self, event_data: Dict[str, Any]) -> List[str]:
        """Generate event tags"""
        tags = []
        
        # Basic tags
        event_type = event_data.get('event_type', 'unknown')
        process_name = event_data.get('process_name', 'unknown')
        severity = event_data.get('severity', 'low')
        threat_indicators = event_data.get('threat_indicators', [])
        
        tags.append(f"event_type:{event_type}")
        tags.append(f"severity:{severity}")
        
        if process_name:
            tags.append(f"process:{process_name}")
        
        # Threat indicator tags
        for indicator in threat_indicators:
            tags.append(f"threat:{indicator}")
        
        # Network-specific tags
        if event_data.get('destination_ip'):
            tags.append(f"network:{event_data['destination_ip']}")
        
        return tags
    
    def _generate_correlation_id(self, event_data: Dict[str, Any]) -> Optional[str]:
        """Generate correlation ID for related events"""
        process_id = event_data.get('process_id')
        process_name = event_data.get('process_name')
        
        # Correlate events by process
        if process_id and process_name:
            return f"process_{process_id}_{process_name}"
        
        return None
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class PrometheusMetrics:
    """Prometheus metrics collection"""
    
    def __init__(self):
        self.enabled = os.getenv("PROMETHEUS_METRICS_ENABLED", "true").lower() == "true"
        
        # Request metrics
        self.request_count = Counter(
            'mary_v5_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status_code', 'risk_level']
        )
        
        self.request_duration = Histogram(
            'mary_v5_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint', 'risk_level'],
            buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        self.request_size = Histogram(
            'mary_v5_request_size_bytes',
            'Request size in bytes',
            ['method', 'endpoint'],
            buckets=[100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000]
        )
        
        # Security metrics
        self.security_events = Counter(
            'mary_v5_security_events_total',
            'Total number of security events',
            ['event_type', 'severity', 'source', 'risk_level']
        )
        
        self.threats_detected = Counter(
            'mary_v5_threats_detected_total',
            'Total number of threats detected',
            ['threat_type', 'severity', 'category']
        )
        
        self.violations = Counter(
            'mary_v5_violations_total',
            'Total number of violations',
            ['violation_type', 'severity', 'source']
        )
        
        self.blocked_requests = Counter(
            'mary_v5_blocked_requests_total',
            'Total number of blocked requests',
            ['reason', 'source_ip', 'risk_level']
        )
        
        # Performance metrics
        self.active_connections = Gauge(
            'mary_v5_active_connections',
            'Number of active connections',
            ['connection_type']
        )
        
        self.queue_size = Gauge(
            'mary_v5_queue_size',
            'Queue size for various components',
            ['queue_name']
        )
        
        self.cache_operations = Counter(
            'mary_v5_cache_operations_total',
            'Total number of cache operations',
            ['operation', 'cache_name', 'result']
        )
        
        self.cache_hit_ratio = Gauge(
            'mary_v5_cache_hit_ratio',
            'Cache hit ratio',
            ['cache_name']
        )
        
        # System metrics
        self.system_cpu_usage = Gauge(
            'mary_v5_system_cpu_usage_percent',
            'System CPU usage percentage'
        )
        
        self.system_memory_usage = Gauge(
            'mary_v5_system_memory_usage_percent',
            'System memory usage percentage'
        )
        
        self.system_disk_usage = Gauge(
            'mary_v5_system_disk_usage_percent',
            'System disk usage percentage',
            ['mount_point']
        )
        
        self.process_memory_usage = Gauge(
            'mary_v5_process_memory_usage_bytes',
            'Process memory usage in bytes'
        )
        
        # WebSocket metrics
        self.websocket_connections = Gauge(
            'mary_v5_websocket_connections',
            'Number of WebSocket connections',
            ['connection_type']
        )
        
        self.websocket_messages = Counter(
            'mary_v5_websocket_messages_total',
            'Total number of WebSocket messages',
            ['direction', 'message_type']
        )
        
        self.logger = get_structured_logger("prometheus_metrics")
        
        self.logger.info("Prometheus metrics initialized", enabled=self.enabled)
    
    def record_request(self, method: str, endpoint: str, status_code: int, 
                       duration: float, size: int, risk_level: str = "low"):
        """Record request metrics"""
        if not self.enabled:
            return
        
        self.request_count.labels(
            method=method,
            endpoint=endpoint,
            status_code=str(status_code),
            risk_level=risk_level
        ).inc()
        
        self.request_duration.labels(
            method=method,
            endpoint=endpoint,
            risk_level=risk_level
        ).observe(duration)
        
        self.request_size.labels(
            method=method,
            endpoint=endpoint
        ).observe(size)
    
    def record_security_event(self, event_type: str, severity: str, 
                            source: str, risk_level: str = "medium"):
        """Record security event"""
        if not self.enabled:
            return
        
        self.security_events.labels(
            event_type=event_type,
            severity=severity,
            source=source,
            risk_level=risk_level
        ).inc()
    
    def record_threat(self, threat_type: str, severity: str, category: str):
        """Record threat detection"""
        if not self.enabled:
            return
        
        self.threats_detected.labels(
            threat_type=threat_type,
            severity=severity,
            category=category
        ).inc()
    
    def record_violation(self, violation_type: str, severity: str, source: str):
        """Record violation"""
        if not self.enabled:
            return
        
        self.violations.labels(
            violation_type=violation_type,
            severity=severity,
            source=source
        ).inc()
    
    def record_blocked_request(self, reason: str, source_ip: str, risk_level: str):
        """Record blocked request"""
        if not self.enabled:
            return
        
        self.blocked_requests.labels(
            reason=reason,
            source_ip=source_ip,
            risk_level=risk_level
        ).inc()
    
    def update_active_connections(self, connection_type: str, count: int):
        """Update active connections gauge"""
        if not self.enabled:
            return
        
        self.active_connections.labels(connection_type=connection_type).set(count)
    
    def update_queue_size(self, queue_name: str, size: int):
        """Update queue size gauge"""
        if not self.enabled:
            return
        
        self.queue_size.labels(queue_name=queue_name).set(size)
    
    def record_cache_operation(self, operation: str, cache_name: str, result: str):
        """Record cache operation"""
        if not self.enabled:
            return
        
        self.cache_operations.labels(
            operation=operation,
            cache_name=cache_name,
            result=result
        ).inc()
    
    def update_cache_hit_ratio(self, cache_name: str, ratio: float):
        """Update cache hit ratio gauge"""
        if not self.enabled:
            return
        
        self.cache_hit_ratio.labels(cache_name=cache_name).set(ratio)
    
    def update_system_metrics(self):
        """Update system metrics"""
        if not self.enabled:
            return
        
        # CPU usage
        cpu_percent = psutil.cpu_percent()
        self.system_cpu_usage.set(cpu_percent)
        
        # Memory usage
        memory = psutil.virtual_memory()
        self.system_memory_usage.set(memory.percent)
        
        # Disk usage
        disk_partitions = psutil.disk_partitions()
        for partition in disk_partitions:
            try:
                disk_usage = psutil.disk_usage(partition.mountpoint)
                self.system_disk_usage.labels(mount_point=partition.mountpoint).set(disk_usage.percent)
            except Exception:
                continue
        
        # Process memory
        process = psutil.Process()
        memory_info = process.memory_info()
        self.process_memory_usage.set(memory_info.rss)
    
    def update_websocket_metrics(self, connection_type: str, connections: int,
                                   messages_sent: int, messages_received: int):
        """Update WebSocket metrics"""
        if not self.enabled:
            return
        
        self.websocket_connections.labels(connection_type=connection_type).set(connections)
        self.websocket_messages.labels(direction="sent", message_type="total").inc(messages_sent)
        self.websocket_messages.labels(direction="received", message_type="total").inc(messages_received)


class ThreatHeatmap:
    """Threat heatmap generation"""
    
    def __init__(self):
        self.enabled = os.getenv("THREAT_HEATMAP_ENABLED", "true").lower() == "true"
        
        # Threat data storage
        self.threat_data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.geographic_data: Dict[str, Dict[str, Any]] = {}
        self.time_window = timedelta(hours=24)
        
        # Heatmap dimensions
        self.heatmap_resolution = {
            "geographic": 50,  # Number of geographic regions
            "temporal": 24,    # Hours in a day
            "severity": 5      # Severity levels
        }
        
        self.logger = get_structured_logger("threat_heatmap")
        
        # Cleanup task
        self.cleanup_task = None
        
        self.logger.info("Threat heatmap initialized", enabled=self.enabled)
    
    async def start(self):
        """Start threat heatmap"""
        if not self.enabled:
            return
        
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_task())
        
        self.logger.info("Threat heatmap started")
    
    async def stop(self):
        """Stop threat heatmap"""
        if not self.enabled:
            return
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Threat heatmap stopped")
    
    async def add_threat_data(self, threat_data: Dict[str, Any]):
        """Add threat data point"""
        if not self.enabled:
            return
        
        # Extract geographic information
        geo_key = threat_data.get("geographic_region", "unknown")
        threat_data["timestamp"] = datetime.utcnow()
        
        # Store threat data
        self.threat_data[geo_key].append(threat_data)
        
        # Update geographic data
        if geo_key not in self.geographic_data:
            self.geographic_data[geo_key] = {
                "total_threats": 0,
                "severity_distribution": defaultdict(int),
                "last_updated": datetime.utcnow()
            }
        
        self.geographic_data[geo_key]["total_threats"] += 1
        self.geographic_data[geo_key]["severity_distribution"][threat_data.get("severity", "medium")] += 1
        self.geographic_data[geo_key]["last_updated"] = datetime.utcnow()
    
    def generate_geographic_heatmap(self) -> Dict[str, Any]:
        """Generate geographic threat heatmap"""
        if not self.enabled:
            return {}
        
        heatmap = {
            "type": "geographic",
            "timestamp": datetime.utcnow().isoformat(),
            "resolution": self.heatmap_resolution["geographic"],
            "data": {}
        }
        
        # Calculate threat density for each region
        max_threats = max(
            data["total_threats"] for data in self.geographic_data.values()
        ) if self.geographic_data else 1
        
        for geo_key, data in self.geographic_data.items():
            # Normalize threat density (0-1)
            density = data["total_threats"] / max_threats
            
            # Calculate severity score
            severity_scores = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4,
                "blocked": 5
            }
            
            severity_score = sum(
                count * severity_scores.get(severity, 0)
                for severity, count in data["severity_distribution"].items()
            ) / max(data["total_threats"], 1)
            
            heatmap["data"][geo_key] = {
                "threat_density": round(density, 3),
                "severity_score": round(severity_score, 3),
                "total_threats": data["total_threats"],
                "last_updated": data["last_updated"].isoformat()
            }
        
        return heatmap
    
    def generate_temporal_heatmap(self) -> Dict[str, Any]:
        """Generate temporal threat heatmap"""
        if not self.enabled:
            return {}
        
        heatmap = {
            "type": "temporal",
            "timestamp": datetime.utcnow().isoformat(),
            "resolution": self.heatmap_resolution["temporal"],
            "data": {}
        }
        
        # Group threats by hour
        current_time = datetime.utcnow()
        threats_by_hour = defaultdict(int)
        
        for geo_key, threats in self.threat_data.items():
            for threat in threats:
                threat_time = threat.get("timestamp", current_time)
                if current_time - threat_time <= self.time_window:
                    hour_key = threat_time.hour
                    threats_by_hour[hour_key] += 1
        
        # Normalize temporal data
        max_threats_hour = max(threats_by_hour.values()) if threats_by_hour else 1
        
        for hour in range(24):
            threat_count = threats_by_hour.get(hour, 0)
            normalized_count = threat_count / max_threats_hour
            
            heatmap["data"][f"hour_{hour:02d}"] = {
                "threat_count": threat_count,
                "normalized_intensity": round(normalized_count, 3)
            }
        
        return heatmap
    
    def generate_severity_heatmap(self) -> Dict[str, Any]:
        """Generate severity-based threat heatmap"""
        if not self.enabled:
            return {}
        
        heatmap = {
            "type": "severity",
            "timestamp": datetime.utcnow().isoformat(),
            "resolution": self.heatmap_resolution["severity"],
            "data": {}
        }
        
        # Count threats by severity
        severity_counts = defaultdict(int)
        
        for geo_key, threats in self.threat_data.items():
            for threat in threats:
                severity = threat.get("severity", "medium")
                severity_counts[severity] += 1
        
        # Normalize severity data
        max_count = max(severity_counts.values()) if severity_counts else 1
        
        for severity, count in severity_counts.items():
            normalized_count = count / max_count
            
            heatmap["data"][severity] = {
                "threat_count": count,
                "normalized_intensity": round(normalized_count, 3)
            }
        
        return heatmap
    
    async def _cleanup_task(self):
        """Cleanup old threat data"""
        while True:
            try:
                await asyncio.sleep(3600)  # 1 hour
                
                cutoff_time = datetime.utcnow() - self.time_window
                
                # Clean old threat data
                for geo_key in list(self.threat_data.keys()):
                    self.threat_data[geo_key] = [
                        threat for threat in self.threat_data[geo_key]
                        if threat.get("timestamp", datetime.utcnow()) > cutoff_time
                    ]
                    
                    if not self.threat_data[geo_key]:
                        del self.threat_data[geo_key]
                
                # Clean old geographic data
                for geo_key in list(self.geographic_data.keys()):
                    if self.geographic_data[geo_key]["last_updated"] < cutoff_time:
                        del self.geographic_data[geo_key]
                
                self.logger.info("Threat heatmap cleanup completed")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Heatmap cleanup error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error


class TelemetryEngine:
    """Main telemetry engine"""
    
    def __init__(self):
        self.enabled = os.getenv("TELEMETRY_ENGINE_ENABLED", "true").lower() == "true"
        
        # Components
        self.prometheus_metrics = PrometheusMetrics()
        self.threat_heatmap = ThreatHeatmap()
        
        # Telemetry configuration
        self.collection_interval = int(os.getenv("TELEMETRY_COLLECTION_INTERVAL", "10"))  # seconds
        self.metrics_endpoint = os.getenv("TELEMETRY_METRICS_ENDPOINT", "/metrics")
        
        # Event storage
        self.events: deque = deque(maxlen=10000)
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        # Statistics
        self.telemetry_stats = {
            "events_collected": 0,
            "metrics_generated": 0,
            "heatmaps_generated": 0,
            "start_time": datetime.utcnow()
        }
        
        # Background tasks
        self.collection_task = None
        self.cleanup_task = None
        
        self.logger = get_structured_logger("telemetry_engine")
        
        # Background tasks will be started by start() method
        
        self.logger.info("Telemetry engine initialized", enabled=self.enabled)
    
    async def start(self):
        """Start telemetry engine"""
        if not self.enabled:
            return
        
        # Start threat heatmap
        await self.threat_heatmap.start()
        
        # Start collection task
        self.collection_task = asyncio.create_task(self._collection_loop())
        
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_task())
        
        self.logger.info("Telemetry engine started")
    
    async def stop(self):
        """Stop telemetry engine"""
        if not self.enabled:
            return
        
        # Stop threat heatmap
        await self.threat_heatmap.stop()
        
        # Cancel background tasks
        if self.collection_task:
            self.collection_task.cancel()
            try:
                await self.collection_task
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Telemetry engine stopped")
    
    async def _collection_loop(self):
        """Main telemetry collection loop"""
        while True:
            try:
                # Collect system metrics
                self.prometheus_metrics.update_system_metrics()
                
                # Update statistics
                self.telemetry_stats["metrics_generated"] += 1
                
                await asyncio.sleep(self.collection_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Telemetry collection error", error=str(e))
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _cleanup_task(self):
        """Periodic cleanup task"""
        while True:
            try:
                # Clean old events (older than 24 hours)
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                old_events = [
                    event for event in self.events
                    if event.timestamp < cutoff_time
                ]
                
                if old_events:
                    # Remove old events
                    for _ in old_events:
                        if self.events:
                            self.events.popleft()
                
                # Wait for next cleanup
                await asyncio.sleep(3600)  # 1 hour
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Telemetry cleanup error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error
    
    async def record_request(self, method: str, endpoint: str, status_code: int, 
                       duration: float, size: int, risk_level: str = "low"):
        """Record request telemetry"""
        if not self.enabled:
            return
        
        self.prometheus_metrics.record_request(
            method, endpoint, status_code, duration, size, risk_level
        )
        
        # Create event
        event = TelemetryEvent(
            metric_name="request",
            value=duration,
            labels={
                "method": method,
                "endpoint": endpoint,
                "status_code": str(status_code),
                "risk_level": risk_level
            },
            metadata={
                "size": size,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        self.events.append(event)
        self.telemetry_stats["events_collected"] += 1
        
        # Notify handlers
        await self._notify_handlers("request", event)
    
    async def record_security_event(self, event_type: str, severity: str, 
                            source: str, risk_level: str = "medium", **kwargs):
        """Record security event telemetry"""
        if not self.enabled:
            return
        
        self.prometheus_metrics.record_security_event(event_type, severity, source, risk_level)
        
        # Create event
        event = TelemetryEvent(
            metric_name="security_event",
            value=1,
            labels={
                "event_type": event_type,
                "severity": severity,
                "source": source,
                "risk_level": risk_level
            },
            metadata=kwargs
        )
        
        self.events.append(event)
        self.telemetry_stats["events_collected"] += 1
        
        # Add to threat heatmap
        await self.threat_heatmap.add_threat_data({
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "risk_level": risk_level,
            "geographic_region": kwargs.get("geographic_region", "unknown"),
            **kwargs
        })
        
        # Notify handlers
        await self._notify_handlers("security_event", event)
    
    async def record_threat(self, threat_type: str, severity: str, category: str, **kwargs):
        """Record threat telemetry"""
        if not self.enabled:
            return
        
        self.prometheus_metrics.record_threat(threat_type, severity, category)
        
        # Create event
        event = TelemetryEvent(
            metric_name="threat",
            value=1,
            labels={
                "threat_type": threat_type,
                "severity": severity,
                "category": category
            },
            metadata=kwargs
        )
        
        self.events.append(event)
        self.telemetry_stats["events_collected"] += 1
        
        # Add to threat heatmap
        await self.threat_heatmap.add_threat_data({
            "threat_type": threat_type,
            "severity": severity,
            "category": category,
            **kwargs
        })
        
        # Notify handlers
        await self._notify_handlers("threat", event)
    
    def register_handler(self, event_type: str, handler: Callable):
        """Register event handler"""
        self.event_handlers[event_type].append(handler)
    
    async def _notify_handlers(self, event_type: str, event: TelemetryEvent):
        """Notify event handlers"""
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                self.logger.error("Telemetry handler error", 
                                handler=str(handler), 
                                error=str(e))
    
    def get_prometheus_metrics(self) -> str:
        """Get Prometheus metrics in text format"""
        if not self.enabled:
            return ""
        
        return generate_latest(REGISTRY).decode('utf-8')
    
    def get_heatmaps(self) -> Dict[str, Any]:
        """Get all heatmaps"""
        if not self.enabled:
            return {}
        
        return {
            "geographic": self.threat_heatmap.generate_geographic_heatmap(),
            "temporal": self.threat_heatmap.generate_temporal_heatmap(),
            "severity": self.threat_heatmap.generate_severity_heatmap()
        }
    
    def get_events(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get telemetry events"""
        if not self.enabled:
            return []
        
        events = list(self.events)
        
        if event_type:
            events = [e for e in events if e.metric_name == event_type]
        
        # Return most recent events
        return [event.to_dict() for event in events[-limit:]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
        if not self.enabled:
            return {"enabled": False}
        
        uptime = datetime.utcnow() - self.telemetry_stats["start_time"]
        
        return {
            "enabled": self.enabled,
            "collection_interval": self.collection_interval,
            "metrics_endpoint": self.metrics_endpoint,
            "uptime_seconds": uptime.total_seconds(),
            **self.telemetry_stats,
            "event_buffer_size": len(self.events),
            "registered_handlers": {
                event_type: len(handlers) 
                for event_type, handlers in self.event_handlers.items()
            }
        }


# Global telemetry engine instance
telemetry_engine = TelemetryEngine()


async def start_telemetry_engine():
    """Start telemetry engine"""
    await telemetry_engine.start()


async def stop_telemetry_engine():
    """Stop telemetry engine"""
    await telemetry_engine.stop()


async def record_request_telemetry(method: str, endpoint: str, status_code: int, 
                            duration: float, size: int, risk_level: str = "low"):
    """Record request telemetry"""
    return await telemetry_engine.record_request(method, endpoint, status_code, duration, size, risk_level)


async def record_security_telemetry(event_type: str, severity: str, source: str, 
                            risk_level: str = "medium", **kwargs):
    """Record security event telemetry"""
    return await telemetry_engine.record_security_event(event_type, severity, source, risk_level, **kwargs)


async def record_threat_telemetry(threat_type: str, severity: str, category: str, **kwargs):
    """Record threat telemetry"""
    return await telemetry_engine.record_threat(threat_type, severity, category, **kwargs)


def get_prometheus_metrics() -> str:
    """Get Prometheus metrics"""
    return telemetry_engine.get_prometheus_metrics()


def get_telemetry_heatmaps() -> Dict[str, Any]:
    """Get threat heatmaps"""
    return telemetry_engine.get_heatmaps()


def get_telemetry_statistics() -> Dict[str, Any]:
    """Get telemetry statistics"""
    return telemetry_engine.get_statistics()
