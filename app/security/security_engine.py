"""
MARY V5 SHIELD CORE - Central Security Engine
Advanced defensive cyber resilience architecture with threat orchestration
"""

import os
import asyncio
import json
import time
import hashlib
import uuid
from typing import Dict, List, Optional, Any, Set, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
import asyncio
import weakref

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(Enum):
    """Incident lifecycle status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class EventType(Enum):
    """Security event types"""
    AUTHENTICATION_FAILURE = "authentication_failure"
    TOKEN_ABUSE = "token_abuse"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    PROCESS_ANOMALY = "process_anomaly"
    POWERSHELL_SUSPICIOUS = "powershell_suspicious"
    FILE_ENCRYPTION = "file_encryption"
    API_ABUSE = "api_abuse"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE_DETECTED = "malware_detected"
    NETWORK_ANOMALY = "network_anomaly"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class SecurityEvent:
    """Security event data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: EventType = EventType.AUTHENTICATION_FAILURE
    threat_level: ThreatLevel = ThreatLevel.INFO
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    raw_event: Dict[str, Any] = field(default_factory=dict)
    mitigation_actions: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['event_type'] = self.event_type.value
        data['threat_level'] = self.threat_level.value
        return data


@dataclass
class ThreatCorrelation:
    """Threat correlation pattern"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pattern_name: str = ""
    description: str = ""
    event_types: List[EventType] = field(default_factory=list)
    time_window: timedelta = timedelta(minutes=5)
    threshold: int = 3
    severity_boost: float = 0.0
    correlation_rules: List[Callable] = field(default_factory=list)
    
    def matches(self, events: List[SecurityEvent]) -> bool:
        """Check if correlation pattern matches events"""
        if len(events) < self.threshold:
            return False
        
        # Check event types
        event_type_matches = sum(1 for e in events if e.event_type in self.event_types)
        if event_type_matches < self.threshold:
            return False
        
        # Check time window
        if events:
            earliest = min(e.timestamp for e in events)
            latest = max(e.timestamp for e in events)
            if latest - earliest > self.time_window:
                return False
        
        # Apply custom correlation rules
        for rule in self.correlation_rules:
            if not rule(events):
                return False
        
        return True


@dataclass
class Incident:
    """Security incident data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    status: IncidentStatus = IncidentStatus.NEW
    threat_level: ThreatLevel = ThreatLevel.INFO
    title: str = ""
    description: str = ""
    source_events: List[str] = field(default_factory=list)
    correlated_events: List[SecurityEvent] = field(default_factory=list)
    mitigation_actions: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    resolution_time: Optional[datetime] = None
    root_cause: Optional[str] = None
    impact_assessment: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        data['status'] = self.status.value
        data['threat_level'] = self.threat_level.value
        if self.resolution_time:
            data['resolution_time'] = self.resolution_time.isoformat()
        return data


class EventCorrelator:
    """Advanced event correlation engine"""
    
    def __init__(self):
        self.enabled = os.getenv("EVENT_CORRELATOR_ENABLED", "true").lower() == "true"
        
        # Correlation patterns
        self.correlation_patterns = self._load_correlation_patterns()
        
        # Event storage for correlation
        self.event_buffer = deque(maxlen=10000)
        self.correlated_events = defaultdict(list)
        
        # Correlation statistics
        self.correlation_stats = {
            "total_events": 0,
            "correlations_found": 0,
            "patterns_matched": defaultdict(int)
        }
        
        logger.info("Event correlator initialized", enabled=self.enabled)
    
    def _load_correlation_patterns(self) -> List[ThreatCorrelation]:
        """Load correlation patterns"""
        patterns = []
        
        # Repeated authentication failures
        auth_failure_pattern = ThreatCorrelation(
            pattern_name="repeated_auth_failures",
            description="Multiple authentication failures from same source",
            event_types=[EventType.AUTHENTICATION_FAILURE],
            time_window=timedelta(minutes=5),
            threshold=5,
            severity_boost=0.3
        )
        
        def auth_failure_rule(events: List[SecurityEvent]) -> bool:
            """Check if auth failures are from same source"""
            source_ips = set(e.source_ip for e in events if e.source_ip)
            return len(source_ips) == 1  # All from same IP
        
        auth_failure_pattern.correlation_rules = [auth_failure_rule]
        patterns.append(auth_failure_pattern)
        
        # Geographic anomaly pattern
        geo_pattern = ThreatCorrelation(
            pattern_name="geographic_anomaly",
            description="Suspicious geographic activity patterns",
            event_types=[EventType.GEOGRAPHIC_ANOMALY, EventType.AUTHENTICATION_FAILURE],
            time_window=timedelta(minutes=10),
            threshold=3,
            severity_boost=0.4
        )
        
        def geo_rule(events: List[SecurityEvent]) -> bool:
            """Check for geographic anomalies"""
            geo_events = [e for e in events if e.event_type == EventType.GEOGRAPHIC_ANOMALY]
            auth_events = [e for e in events if e.event_type == EventType.AUTHENTICATION_FAILURE]
            return len(geo_events) >= 1 and len(auth_events) >= 2
        
        geo_pattern.correlation_rules = [geo_rule]
        patterns.append(geo_pattern)
        
        # PowerShell suspicious activity
        powershell_pattern = ThreatCorrelation(
            pattern_name="powershell_suspicious_chain",
            description="Chain of suspicious PowerShell activities",
            event_types=[EventType.POWERSHELL_SUSPICIOUS],
            time_window=timedelta(minutes=15),
            threshold=3,
            severity_boost=0.5
        )
        
        def powershell_rule(events: List[SecurityEvent]) -> bool:
            """Check for PowerShell chain"""
            return len(events) >= 3 and all(
                e.details.get("command_type") in ["encoded", "obfuscated", "suspicious"]
                for e in events
            )
        
        powershell_pattern.correlation_rules = [powershell_rule]
        patterns.append(powershell_pattern)
        
        # File encryption pattern
        encryption_pattern = ThreatCorrelation(
            pattern_name="file_encryption_burst",
            description="Rapid file encryption activity",
            event_types=[EventType.FILE_ENCRYPTION],
            time_window=timedelta(minutes=2),
            threshold=10,
            severity_boost=0.6
        )
        
        def encryption_rule(events: List[SecurityEvent]) -> bool:
            """Check for encryption burst"""
            return len(events) >= 10
        
        encryption_pattern.correlation_rules = [encryption_rule]
        patterns.append(encryption_pattern)
        
        # API abuse pattern
        api_abuse_pattern = ThreatCorrelation(
            pattern_name="api_abuse_burst",
            description="High-frequency API abuse",
            event_types=[EventType.API_ABUSE],
            time_window=timedelta(minutes=1),
            threshold=100,
            severity_boost=0.4
        )
        
        def api_abuse_rule(events: List[SecurityEvent]) -> bool:
            """Check for API abuse"""
            return len(events) >= 100
        
        api_abuse_pattern.correlation_rules = [api_abuse_rule]
        patterns.append(api_abuse_pattern)
        
        return patterns
    
    async def correlate_events(self, event: SecurityEvent) -> List[ThreatCorrelation]:
        """Correlate event with existing events"""
        if not self.enabled:
            return []
        
        correlations = []
        
        # Add event to buffer
        self.event_buffer.append(event)
        self.correlation_stats["total_events"] += 1
        
        # Check each correlation pattern
        for pattern in self.correlation_patterns:
            # Get relevant events from buffer
            relevant_events = [
                e for e in self.event_buffer
                if e.event_type in pattern.event_types
                and (datetime.utcnow() - e.timestamp) <= pattern.time_window
            ]
            
            # Include current event
            relevant_events.append(event)
            
            # Check if pattern matches
            if pattern.matches(relevant_events):
                correlations.append(pattern)
                self.correlation_stats["correlations_found"] += 1
                self.correlation_stats["patterns_matched"][pattern.pattern_name] += 1
                
                # Boost threat level based on pattern
                severity_boost = pattern.severity_boost
                current_level = self._get_threat_level_value(event.threat_level)
                new_level_value = min(1.0, current_level + severity_boost)
                event.threat_level = self._get_threat_level_from_value(new_level_value)
        
        return correlations
    
    def _get_threat_level_value(self, level: ThreatLevel) -> float:
        """Get numeric value for threat level"""
        values = {
            ThreatLevel.INFO: 0.1,
            ThreatLevel.LOW: 0.3,
            ThreatLevel.MEDIUM: 0.5,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.CRITICAL: 0.9
        }
        return values.get(level, 0.1)
    
    def _get_threat_level_from_value(self, value: float) -> ThreatLevel:
        """Get threat level from numeric value"""
        if value >= 0.8:
            return ThreatLevel.CRITICAL
        elif value >= 0.6:
            return ThreatLevel.HIGH
        elif value >= 0.4:
            return ThreatLevel.MEDIUM
        elif value >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO
    
    def get_correlation_stats(self) -> Dict[str, Any]:
        """Get correlation statistics"""
        return {
            "enabled": self.enabled,
            "buffer_size": len(self.event_buffer),
            "patterns_loaded": len(self.correlation_patterns),
            **self.correlation_stats
        }


class ThreatOrchestrator:
    """Central threat orchestration and mitigation"""
    
    def __init__(self):
        self.enabled = os.getenv("THREAT_ORCHESTRATOR_ENABLED", "true").lower() == "true"
        
        # Mitigation hooks
        self.mitigation_hooks = defaultdict(list)
        
        # Incident management
        self.active_incidents = {}
        self.incident_history = deque(maxlen=1000)
        
        # Threat scoring
        self.threat_weights = {
            ThreatLevel.INFO: 1,
            ThreatLevel.LOW: 5,
            ThreatLevel.MEDIUM: 15,
            ThreatLevel.HIGH: 30,
            ThreatLevel.CRITICAL: 50
        }
        
        logger.info("Threat orchestrator initialized", enabled=self.enabled)
    
    def register_mitigation_hook(self, event_type: EventType, hook: Callable):
        """Register mitigation hook for event type"""
        self.mitigation_hooks[event_type].append(hook)
    
    async def process_event(self, event: SecurityEvent) -> Incident:
        """Process security event and create incident if needed"""
        if not self.enabled:
            return Incident()
        
        # Calculate threat score
        threat_score = self._calculate_threat_score(event)
        
        # Determine if incident should be created
        if threat_score >= self.threat_weights[ThreatLevel.MEDIUM]:
            incident = await self._create_incident(event, threat_score)
            
            # Execute mitigation hooks
            await self._execute_mitigation_hooks(event, incident)
            
            return incident
        
        return None
    
    def _calculate_threat_score(self, event: SecurityEvent) -> int:
        """Calculate threat score for event"""
        base_score = self.threat_weights[event.threat_level]
        
        # Add context-based scoring
        context_boost = 0
        
        # Multiple failed attempts
        if event.details.get("attempt_count", 0) > 5:
            context_boost += 10
        
        # Suspicious user agent
        if event.details.get("suspicious_user_agent"):
            context_boost += 5
        
        # Geographic anomaly
        if event.event_type == EventType.GEOGRAPHIC_ANOMALY:
            context_boost += 15
        
        # PowerShell suspicious
        if event.event_type == EventType.POWERSHELL_SUSPICIOUS:
            context_boost += 20
        
        return base_score + context_boost
    
    async def _create_incident(self, event: SecurityEvent, threat_score: int) -> Incident:
        """Create security incident"""
        incident = Incident(
            title=f"{event.event_type.value.replace('_', ' ').title()} - {event.threat_level.value.upper()}",
            description=event.description,
            threat_level=event.threat_level,
            source_events=[event.id],
            correlated_events=[event],
            impact_assessment={
                "threat_score": threat_score,
                "affected_systems": ["api", "authentication"],
                "potential_impact": "medium" if threat_score < 30 else "high"
            }
        )
        
        self.active_incidents[incident.id] = incident
        self.incident_history.append(incident)
        
        # Log incident creation
        log_security_event(
            "incident_created",
            {
                "incident_id": incident.id,
                "threat_level": incident.threat_level.value,
                "threat_score": threat_score,
                "event_type": event.event_type.value
            }
        )
        
        return incident
    
    async def _execute_mitigation_hooks(self, event: SecurityEvent, incident: Incident):
        """Execute mitigation hooks for event"""
        hooks = self.mitigation_hooks.get(event.event_type, [])
        
        for hook in hooks:
            try:
                await hook(event, incident)
                incident.mitigation_actions.append(hook.__name__)
            except Exception as e:
                logger.error(f"Mitigation hook failed: {hook.__name__}", error=str(e))
    
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        """Update incident status and details"""
        if incident_id not in self.active_incidents:
            return False
        
        incident = self.active_incidents[incident_id]
        
        for key, value in updates.items():
            if hasattr(incident, key):
                setattr(incident, key, value)
        
        incident.updated_at = datetime.utcnow()
        
        # Log incident update
        log_audit_event(
            "incident_updated",
            resource=f"incident:{incident_id}",
            result="success",
            details=updates
        )
        
        return True
    
    async def resolve_incident(self, incident_id: str, resolution: str) -> bool:
        """Resolve incident"""
        if incident_id not in self.active_incidents:
            return False
        
        incident = self.active_incidents[incident_id]
        incident.status = IncidentStatus.RESOLVED
        incident.resolution_time = datetime.utcnow()
        incident.root_cause = resolution
        
        # Move to history
        self.incident_history.append(incident)
        del self.active_incidents[incident_id]
        
        # Log incident resolution
        log_audit_event(
            "incident_resolved",
            resource=f"incident:{incident_id}",
            result="success",
            details={"resolution": resolution}
        )
        
        return True
    
    def get_incident_summary(self) -> Dict[str, Any]:
        """Get incident summary"""
        return {
            "active_incidents": len(self.active_incidents),
            "total_incidents": len(self.incident_history),
            "by_status": self._count_incidents_by_status(),
            "by_threat_level": self._count_incidents_by_level(),
            "enabled": self.enabled
        }
    
    def _count_incidents_by_status(self) -> Dict[str, int]:
        """Count incidents by status"""
        status_counts = defaultdict(int)
        
        for incident in self.active_incidents.values():
            status_counts[incident.status.value] += 1
        
        return dict(status_counts)
    
    def _count_incidents_by_level(self) -> Dict[str, int]:
        """Count incidents by threat level"""
        level_counts = defaultdict(int)
        
        for incident in self.active_incidents.values():
            level_counts[incident.threat_level.value] += 1
        
        return dict(level_counts)


class SecurityEngine:
    """Central security engine orchestrating all defensive components"""
    
    def __init__(self):
        self.enabled = os.getenv("SECURITY_ENGINE_ENABLED", "true").lower() == "true"
        
        # Core components
        self.event_correlator = EventCorrelator()
        self.threat_orchestrator = ThreatOrchestrator()
        
        # Event processing
        self.event_queue = asyncio.Queue(maxsize=1000)
        self.processing_workers = []
        self.max_workers = int(os.getenv("SECURITY_ENGINE_WORKERS", "4"))
        
        # WebSocket connections for real-time updates
        self.websocket_connections = weakref.WeakSet()
        
        # Statistics
        self.engine_stats = {
            "events_processed": 0,
            "incidents_created": 0,
            "correlations_found": 0,
            "mitigations_executed": 0,
            "start_time": datetime.utcnow()
        }
        
        logger.info("Security engine initialized", enabled=self.enabled)
    
    async def start(self):
        """Start security engine"""
        if not self.enabled:
            return
        
        # Start processing workers
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._event_worker(f"worker-{i}"))
            self.processing_workers.append(worker)
        
        logger.info(f"Security engine started with {self.max_workers} workers")
    
    async def stop(self):
        """Stop security engine"""
        if not self.enabled:
            return
        
        # Cancel workers
        for worker in self.processing_workers:
            worker.cancel()
        
        await asyncio.gather(*self.processing_workers, return_exceptions=True)
        
        self.processing_workers.clear()
        logger.info("Security engine stopped")
    
    async def process_event(self, event_data: Dict[str, Any]) -> Optional[Incident]:
        """Process security event through the engine"""
        if not self.enabled:
            return None
        
        # Create SecurityEvent
        event = SecurityEvent(
            event_type=EventType(event_data.get("event_type", "authentication_failure")),
            threat_level=ThreatLevel(event_data.get("threat_level", "info")),
            source_ip=event_data.get("source_ip"),
            user_id=event_data.get("user_id"),
            session_id=event_data.get("session_id"),
            correlation_id=event_data.get("correlation_id"),
            description=event_data.get("description", ""),
            details=event_data.get("details", {}),
            raw_event=event_data
        )
        
        # Add to processing queue
        await self.event_queue.put(event)
        
        # Return placeholder (actual processing happens in workers)
        return None
    
    async def _event_worker(self, worker_name: str):
        """Event processing worker"""
        logger.info(f"{worker_name} started")
        
        while True:
            try:
                # Get event from queue
                event = await asyncio.wait_for(
                    self.event_queue.get(),
                    timeout=1.0
                )
                
                # Process event through correlator
                correlations = await self.event_correlator.correlate_events(event)
                
                # Process through orchestrator
                incident = await self.threat_orchestrator.process_event(event)
                
                # Update statistics
                self.engine_stats["events_processed"] += 1
                if incident:
                    self.engine_stats["incidents_created"] += 1
                
                if correlations:
                    self.engine_stats["correlations_found"] += len(correlations)
                
                # Broadcast to WebSocket connections
                await self._broadcast_event(event, incident, correlations)
                
                self.event_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"{worker_name} error", error=str(e))
    
    async def _broadcast_event(self, event: SecurityEvent, incident: Optional[Incident], 
                           correlations: List[ThreatCorrelation]):
        """Broadcast event to WebSocket connections"""
        if not self.websocket_connections:
            return
        
        broadcast_data = {
            "type": "security_event",
            "timestamp": datetime.utcnow().isoformat(),
            "event": event.to_dict(),
            "incident": incident.to_dict() if incident else None,
            "correlations": [asdict(c) for c in correlations],
            "stats": self.engine_stats
        }
        
        # Send to all connected clients
        disconnected = set()
        for ws in list(self.websocket_connections):
            try:
                await ws.send(json.dumps(broadcast_data, default=str))
            except Exception:
                disconnected.add(ws)
        
        # Clean up disconnected connections
        for ws in disconnected:
            self.websocket_connections.discard(ws)
    
    def register_websocket(self, websocket):
        """Register WebSocket connection"""
        self.websocket_connections.add(websocket)
    
    def unregister_websocket(self, websocket):
        """Unregister WebSocket connection"""
        self.websocket_connections.discard(websocket)
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get engine status and statistics"""
        uptime = datetime.utcnow() - self.engine_stats["start_time"]
        
        return {
            "enabled": self.enabled,
            "status": "running" if self.processing_workers else "stopped",
            "workers": len(self.processing_workers),
            "queue_size": self.event_queue.qsize(),
            "websocket_connections": len(self.websocket_connections),
            "statistics": self.engine_stats,
            "uptime_seconds": uptime.total_seconds(),
            "correlator_stats": self.event_correlator.get_correlation_stats(),
            "incident_summary": self.threat_orchestrator.get_incident_summary()
        }


# Global security engine instance
security_engine = SecurityEngine()


async def start_security_engine():
    """Start security engine"""
    await security_engine.start()


async def stop_security_engine():
    """Stop security engine"""
    await security_engine.stop()


async def process_security_event(event_data: Dict[str, Any]) -> Optional[Incident]:
    """Process security event"""
    return await security_engine.process_event(event_data)


def get_security_engine_status() -> Dict[str, Any]:
    """Get security engine status"""
    return security_engine.get_engine_status()
