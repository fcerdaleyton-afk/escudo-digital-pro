#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Sysmon Telemetry Engine
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
            logging.FileHandler(os.path.join(log_dir, 'sysmon_telemetry_engine.log')),
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


class SysmonTelemetryEngine:
    """Comprehensive telemetry engine with Sysmon integration and event forwarding"""
    
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
        
        logger.info("Sysmon telemetry engine initialized")
    
    async def start(self):
        """Start telemetry engine"""
        try:
            logger.info("Starting Sysmon telemetry engine")
            
            self.is_running = True
            
            # Setup Sysmon integration
            add_sysmon_callback(self._handle_sysmon_event)
            
            # Start background tasks
            asyncio.create_task(self._process_event_queue())
            asyncio.create_task(self._cleanup_old_events())
            asyncio.create_task(self._generate_statistics_report())
            
            logger.info("Sysmon telemetry engine started successfully")
            
        except Exception as e:
            logger.error(f"Error starting telemetry engine: {e}")
            raise
    
    async def stop(self):
        """Stop telemetry engine"""
        try:
            logger.info("Stopping Sysmon telemetry engine")
            
            self.is_running = False
            
            logger.info("Sysmon telemetry engine stopped successfully")
            
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
    
    async def _process_event_queue(self):
        """Process event queue"""
        try:
            batch = []
            
            while self.is_running:
                try:
                    # Collect batch of events
                    try:
                        event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                        batch.append(event)
                    except asyncio.TimeoutError:
                        if batch:
                            await self._process_event_batch(batch)
                            batch = []
                        continue
                    
                    # Process batch when full or timeout
                    if len(batch) >= self.config['batch_processing_size']:
                        await self._process_event_batch(batch)
                        batch = []
                        
                except Exception as e:
                    logger.error(f"Error processing event queue: {e}")
                    await asyncio.sleep(5)
                    
        except Exception as e:
            logger.error(f"Event queue processing error: {e}")
    
    async def _process_event_batch(self, events: List[TelemetryEvent]):
        """Process batch of events"""
        try:
            for event in events:
                # Store event
                self.processed_events.append(event)
                
                # Update statistics
                self.stats['total_events'] += 1
                self.stats['events_by_type'][event.event_type.value] += 1
                self.stats['events_by_priority'][event.priority.value] += 1
                self.stats['events_by_severity'][event.severity] += 1
                
                # Forward to destinations
                await self._forward_to_websocket(event)
                await self._forward_to_incidents(event)
                await self._forward_to_audit_logs(event)
                await self._forward_to_threat_detection(event)
                
                logger.debug(f"Processed event: {event.event_type.value} - {event.title}")
            
        except Exception as e:
            logger.error(f"Error processing event batch: {e}")
    
    async def _forward_to_websocket(self, event: TelemetryEvent):
        """Forward event to WebSocket telemetry"""
        try:
            if not self.config['websocket_enabled'] or not self.websocket_clients:
                return
            
            # Send to all WebSocket clients
            for client_callback in self.websocket_clients:
                try:
                    await client_callback({
                        'type': 'telemetry_event',
                        'data': event.to_dict()
                    })
                except Exception as e:
                    logger.error(f"Error sending to WebSocket client: {e}")
                    
        except Exception as e:
            logger.error(f"Error forwarding to WebSocket: {e}")
    
    async def _forward_to_incidents(self, event: TelemetryEvent):
        """Forward event to incidents"""
        try:
            if not self.config['incident_generation_enabled'] or not self.incident_callbacks:
                return
            
            # Create incident for high/critical events
            if event.priority in [EventPriority.HIGH, EventPriority.CRITICAL]:
                incident_data = {
                    'incident_id': str(uuid.uuid4()),
                    'timestamp': event.timestamp,
                    'severity': event.severity,
                    'title': f"Security Incident: {event.title}",
                    'description': event.description,
                    'source': event.source,
                    'event_data': event.data,
                    'status': 'open',
                    'correlation_id': event.correlation_id
                }
                
                # Send to incident callbacks
                for callback in self.incident_callbacks:
                    try:
                        await callback({
                            'type': 'incident',
                            'data': incident_data
                        })
                    except Exception as e:
                        logger.error(f"Error in incident callback: {e}")
                
                self.stats['incidents_generated'] += 1
                logger.info(f"Incident generated: {event.title}")
                
        except Exception as e:
            logger.error(f"Error forwarding to incidents: {e}")
    
    async def _forward_to_audit_logs(self, event: TelemetryEvent):
        """Forward event to audit logs"""
        try:
            if not self.config['audit_logging_enabled'] or not self.audit_callbacks:
                return
            
            # Create audit log entry
            audit_entry = {
                'audit_id': str(uuid.uuid4()),
                'timestamp': event.timestamp,
                'event_type': event.event_type.value,
                'source': event.source,
                'action': 'event_detected',
                'object': event.title,
                'details': event.description,
                'user': event.data.get('user', 'system'),
                'computer': event.data.get('computer_name', 'unknown'),
                'severity': event.severity,
                'event_data': event.data
            }
            
            # Send to audit callbacks
            for callback in self.audit_callbacks:
                try:
                    await callback({
                        'type': 'audit_log',
                        'data': audit_entry
                    })
                except Exception as e:
                    logger.error(f"Error in audit callback: {e}")
            
            self.stats['audit_logs_generated'] += 1
            logger.debug(f"Audit log generated: {event.title}")
            
        except Exception as e:
            logger.error(f"Error forwarding to audit logs: {e}")
    
    async def _forward_to_threat_detection(self, event: TelemetryEvent):
        """Forward event to threat detection panel"""
        try:
            if not self.config['threat_detection_enabled'] or not self.threat_callbacks:
                return
            
            # Create threat detection entry
            threat_data = {
                'threat_id': str(uuid.uuid4()),
                'timestamp': event.timestamp,
                'threat_type': event.event_type.value,
                'severity': event.severity,
                'confidence': self._calculate_confidence(event),
                'source': event.source,
                'title': event.title,
                'description': event.description,
                'indicators': event.data.get('threat_indicators', []),
                'process_info': {
                    'pid': event.data.get('process_id'),
                    'name': event.data.get('process_name'),
                    'command_line': event.data.get('command_line'),
                    'parent_pid': event.data.get('parent_process_id'),
                    'parent_name': event.data.get('parent_process_name')
                },
                'network_info': {
                    'destination_ip': event.data.get('destination_ip'),
                    'destination_port': event.data.get('destination_port'),
                    'source_ip': event.data.get('source_ip'),
                    'source_port': event.data.get('source_port'),
                    'protocol': event.data.get('network_protocol')
                },
                'status': 'detected',
                'correlation_id': event.correlation_id
            }
            
            # Send to threat detection callbacks
            for callback in self.threat_callbacks:
                try:
                    await callback({
                        'type': 'threat_detection',
                        'data': threat_data
                    })
                except Exception as e:
                    logger.error(f"Error in threat detection callback: {e}")
            
            self.stats['threat_detections_generated'] += 1
            logger.info(f"Threat detection generated: {event.title}")
            
        except Exception as e:
            logger.error(f"Error forwarding to threat detection: {e}")
    
    def _calculate_confidence(self, event: TelemetryEvent) -> float:
        """Calculate threat confidence score"""
        try:
            base_confidence = 0.5
            
            # Increase confidence based on threat indicators
            threat_indicators = event.data.get('threat_indicators', [])
            indicator_count = len(threat_indicators)
            
            # High confidence indicators
            high_confidence_indicators = ['encoded_powershell', 'suspicious_parent_child']
            for indicator in threat_indicators:
                if indicator in high_confidence_indicators:
                    base_confidence += 0.3
            
            # Medium confidence indicators
            medium_confidence_indicators = ['suspicious_process', 'suspicious_command', 'suspicious_port']
            for indicator in threat_indicators:
                if indicator in medium_confidence_indicators:
                    base_confidence += 0.2
            
            # Adjust based on severity
            if event.severity == 'critical':
                base_confidence += 0.2
            elif event.severity == 'high':
                base_confidence += 0.1
            
            # Cap at 1.0
            return min(base_confidence, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating confidence: {e}")
            return 0.5
    
    async def _cleanup_old_events(self):
        """Cleanup old events"""
        try:
            while self.is_running:
                # Cleanup every hour
                await asyncio.sleep(3600)
                
                cutoff_time = datetime.utcnow() - timedelta(hours=self.config['event_retention_hours'])
                
                # Remove old events
                old_events_count = 0
                while self.processed_events and self.processed_events[0].timestamp < cutoff_time:
                    self.processed_events.popleft()
                    old_events_count += 1
                
                if old_events_count > 0:
                    logger.info(f"Cleaned up {old_events_count} old telemetry events")
                    
        except Exception as e:
            logger.error(f"Event cleanup error: {e}")
    
    async def _generate_statistics_report(self):
        """Generate periodic statistics report"""
        try:
            while self.is_running:
                # Generate report every 10 minutes
                await asyncio.sleep(600)
                
                logger.info(f"Telemetry Statistics: {self.stats}")
                
        except Exception as e:
            logger.error(f"Statistics report error: {e}")
    
    def get_events(self, limit: int = 1000, event_type: Optional[str] = None,
                   severity: Optional[str] = None, priority: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get telemetry events"""
        try:
            events = list(self.processed_events)
            
            # Apply filters
            if event_type:
                events = [e for e in events if e.event_type.value == event_type]
            
            if severity:
                events = [e for e in events if e.severity == severity]
            
            if priority:
                events = [e for e in events if e.priority.value == priority]
            
            # Sort by timestamp (most recent first)
            events.sort(key=lambda x: x.timestamp, reverse=True)
            
            # Limit results
            events = events[:limit]
            
            return [event.to_dict() for event in events]
            
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get telemetry engine statistics"""
        try:
            return {
                'is_running': self.is_running,
                'queue_size': self.event_queue.qsize(),
                'total_events': self.stats['total_events'],
                'event_history_size': len(self.processed_events),
                'websocket_clients': self.stats['websocket_clients'],
                'events_by_type': dict(self.stats['events_by_type']),
                'events_by_priority': dict(self.stats['events_by_priority']),
                'events_by_severity': dict(self.stats['events_by_severity']),
                'incidents_generated': self.stats['incidents_generated'],
                'audit_logs_generated': self.stats['audit_logs_generated'],
                'threat_detections_generated': self.stats['threat_detections_generated'],
                'config': self.config
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {'error': str(e)}


# Global telemetry engine instance
sysmon_telemetry_engine = SysmonTelemetryEngine()


# API functions
async def start_sysmon_telemetry_engine() -> str:
    """Start Sysmon telemetry engine"""
    try:
        await sysmon_telemetry_engine.start()
        logger.info("Sysmon telemetry engine started")
        return "Sysmon telemetry engine started successfully"
    except Exception as e:
        logger.error(f"Error starting Sysmon telemetry engine: {e}")
        return f"Error starting Sysmon telemetry engine: {e}"


async def stop_sysmon_telemetry_engine() -> str:
    """Stop Sysmon telemetry engine"""
    try:
        await sysmon_telemetry_engine.stop()
        logger.info("Sysmon telemetry engine stopped")
        return "Sysmon telemetry engine stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping Sysmon telemetry engine: {e}")
        return f"Error stopping Sysmon telemetry engine: {e}"


def get_sysmon_telemetry_events(limit: int = 1000, event_type: Optional[str] = None,
                        severity: Optional[str] = None, priority: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get Sysmon telemetry events"""
    try:
        return sysmon_telemetry_engine.get_events(limit, event_type, severity, priority)
    except Exception as e:
        logger.error(f"Error getting Sysmon telemetry events: {e}")
        return []


def get_sysmon_telemetry_statistics() -> Dict[str, Any]:
    """Get Sysmon telemetry engine statistics"""
    try:
        return sysmon_telemetry_engine.get_statistics()
    except Exception as e:
        logger.error(f"Error getting Sysmon telemetry statistics: {e}")
        return {'error': str(e)}


def add_sysmon_websocket_client(callback: Callable):
    """Add WebSocket client"""
    try:
        sysmon_telemetry_engine.add_websocket_client(callback)
        logger.info("WebSocket client added to Sysmon telemetry engine")
    except Exception as e:
        logger.error(f"Error adding WebSocket client: {e}")


def remove_sysmon_websocket_client(callback: Callable):
    """Remove WebSocket client"""
    try:
        sysmon_telemetry_engine.remove_websocket_client(callback)
        logger.info("WebSocket client removed from Sysmon telemetry engine")
    except Exception as e:
        logger.error(f"Error removing WebSocket client: {e}")


def add_sysmon_incident_callback(callback: Callable):
    """Add incident callback"""
    try:
        sysmon_telemetry_engine.add_incident_callback(callback)
        logger.info("Incident callback added to Sysmon telemetry engine")
    except Exception as e:
        logger.error(f"Error adding incident callback: {e}")


def add_sysmon_audit_callback(callback: Callable):
    """Add audit callback"""
    try:
        sysmon_telemetry_engine.add_audit_callback(callback)
        logger.info("Audit callback added to Sysmon telemetry engine")
    except Exception as e:
        logger.error(f"Error adding audit callback: {e}")


def add_sysmon_threat_callback(callback: Callable):
    """Add threat detection callback"""
    try:
        sysmon_telemetry_engine.add_threat_callback(callback)
        logger.info("Threat detection callback added to Sysmon telemetry engine")
    except Exception as e:
        logger.error(f"Error adding threat detection callback: {e}"


# Initialize Sysmon telemetry engine
async def initialize_sysmon_telemetry_engine() -> str:
    """Initialize Sysmon telemetry engine"""
    try:
        await start_sysmon_telemetry_engine()
        logger.info("Sysmon telemetry engine initialized")
        return "Sysmon telemetry engine initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing Sysmon telemetry engine: {e}")
        return f"Error initializing Sysmon telemetry engine: {e}"


# Cleanup function
async def cleanup_sysmon_telemetry_engine() -> str:
    """Cleanup Sysmon telemetry engine"""
    try:
        await stop_sysmon_telemetry_engine()
        logger.info("Sysmon telemetry engine cleaned up")
        return "Sysmon telemetry engine cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up Sysmon telemetry engine: {e}")
        return f"Error cleaning up Sysmon telemetry engine: {e}"
