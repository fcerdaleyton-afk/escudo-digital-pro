"""
MARY V5 SHIELD CORE - Incident Response Engine
Automatic alert escalation, incident classification, mitigation suggestions, and lifecycle tracking
"""

import os
import time
import asyncio
import json
import uuid
from typing import Dict, List, Optional, Any, Set, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import threading
import weakref

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger
from app.core.security_settings import get_security_settings


class IncidentSeverity(Enum):
    """Incident severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(Enum):
    """Incident status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    IDENTIFIED = "identified"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"


class IncidentCategory(Enum):
    """Incident categories"""
    SECURITY_BREACH = "security_breach"
    THREAT_DETECTION = "threat_detection"
    SYSTEM_FAILURE = "system_failure"
    DATA_COMPROMISE = "data_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE_DETECTION = "malware_detection"
    NETWORK_ATTACK = "network_attack"
    AUTHENTICATION_FAILURE = "authentication_failure"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    COMPLIANCE_VIOLATION = "compliance_violation"


class EscalationLevel(Enum):
    """Escalation levels"""
    LEVEL_1 = "level_1"  # Automated response
    LEVEL_2 = "level_2"  # Security team notification
    LEVEL_3 = "level_3"  # Management notification
    LEVEL_4 = "level_4"  # Executive notification
    LEVEL_5 = "level_5"  # Emergency response


@dataclass
class Incident:
    """Incident data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    category: IncidentCategory = IncidentCategory.THREAT_DETECTION
    status: IncidentStatus = IncidentStatus.NEW
    title: str = ""
    description: str = ""
    source: str = ""
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    
    # Incident details
    affected_assets: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    impact_assessment: Dict[str, Any] = field(default_factory=dict)
    
    # Response information
    escalation_level: EscalationLevel = EscalationLevel.LEVEL_1
    assigned_to: Optional[str] = None
    mitigation_actions: List[str] = field(default_factory=list)
    resolution_notes: str = ""
    
    # Timeline
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        data['category'] = self.category.value
        data['escalation_level'] = self.escalation_level.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        if self.resolved_at:
            data['resolved_at'] = self.resolved_at.isoformat()
        if self.closed_at:
            data['closed_at'] = self.closed_at.isoformat()
        return data


@dataclass
class MitigationAction:
    """Mitigation action data structure"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    action_type: str = ""
    description: str = ""
    priority: str = "medium"
    automated: bool = False
    executed: bool = False
    executed_at: Optional[datetime] = None
    executed_by: Optional[str] = None
    result: Optional[str] = None
    success: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        if self.executed_at:
            data['executed_at'] = self.executed_at.isoformat()
        return data


class IncidentClassifier:
    """Incident classification engine"""
    
    def __init__(self):
        self.enabled = os.getenv("INCIDENT_CLASSIFIER_ENABLED", "true").lower() == "true"
        
        # Classification rules
        self.classification_rules = self._load_classification_rules()
        
        # Severity thresholds
        self.severity_thresholds = {
            "critical_keywords": ["critical", "emergency", "breach", "compromise", "malware"],
            "high_keywords": ["attack", "intrusion", "unauthorized", "suspicious", "anomaly"],
            "medium_keywords": ["alert", "warning", "detection", "monitor"],
            "low_keywords": ["info", "log", "routine", "normal"]
        }
        
        self.logger = get_structured_logger("incident_classifier")
        
        self.logger.info("Incident classifier initialized", enabled=self.enabled)
    
    def _load_classification_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load classification rules"""
        return {
            IncidentCategory.SECURITY_BREACH: [
                {
                    "keywords": ["breach", "compromise", "unauthorized access", "data leak"],
                    "severity": IncidentSeverity.CRITICAL,
                    "escalation": EscalationLevel.LEVEL_3
                }
            ],
            IncidentCategory.THREAT_DETECTION: [
                {
                    "keywords": ["threat", "attack", "malware", "intrusion"],
                    "severity": IncidentSeverity.HIGH,
                    "escalation": EscalationLevel.LEVEL_2
                }
            ],
            IncidentCategory.SYSTEM_FAILURE: [
                {
                    "keywords": ["failure", "crash", "error", "down"],
                    "severity": IncidentSeverity.MEDIUM,
                    "escalation": EscalationLevel.LEVEL_1
                }
            ],
            IncidentCategory.PRIVILEGE_ESCALATION: [
                {
                    "keywords": ["privilege", "escalation", "admin", "root"],
                    "severity": IncidentSeverity.HIGH,
                    "escalation": EscalationLevel.LEVEL_2
                }
            ],
            IncidentCategory.MALWARE_DETECTION: [
                {
                    "keywords": ["malware", "virus", "trojan", "ransomware"],
                    "severity": IncidentSeverity.CRITICAL,
                    "escalation": EscalationLevel.LEVEL_3
                }
            ],
            IncidentCategory.NETWORK_ATTACK: [
                {
                    "keywords": ["ddos", "dos", "flood", "scan"],
                    "severity": IncidentSeverity.HIGH,
                    "escalation": EscalationLevel.LEVEL_2
                }
            ],
            IncidentCategory.AUTHENTICATION_FAILURE: [
                {
                    "keywords": ["login", "auth", "credential", "password"],
                    "severity": IncidentSeverity.MEDIUM,
                    "escalation": EscalationLevel.LEVEL_1
                }
            ]
        }
    
    def classify_incident(self, title: str, description: str, source: str, 
                         additional_data: Dict[str, Any] = None) -> Tuple[IncidentCategory, IncidentSeverity, EscalationLevel]:
        """Classify incident based on content"""
        if not self.enabled:
            return IncidentCategory.THREAT_DETECTION, IncidentSeverity.MEDIUM, EscalationLevel.LEVEL_1
        
        # Combine all text for analysis
        text = f"{title} {description} {source}".lower()
        if additional_data:
            text += " " + " ".join(str(v) for v in additional_data.values())
        
        # Initialize defaults
        best_category = IncidentCategory.THREAT_DETECTION
        best_severity = IncidentSeverity.MEDIUM
        best_escalation = EscalationLevel.LEVEL_1
        best_score = 0
        
        # Check classification rules
        for category, rules in self.classification_rules.items():
            for rule in rules:
                score = 0
                for keyword in rule["keywords"]:
                    if keyword in text:
                        score += 1
                
                if score > best_score:
                    best_score = score
                    best_category = category
                    best_severity = rule["severity"]
                    best_escalation = rule["escalation"]
        
        # Adjust severity based on keywords
        for severity, keywords in self.severity_thresholds.items():
            for keyword in keywords:
                if keyword in text:
                    if severity == "critical_keywords":
                        best_severity = IncidentSeverity.CRITICAL
                        best_escalation = EscalationLevel.LEVEL_4
                    elif severity == "high_keywords" and best_severity != IncidentSeverity.CRITICAL:
                        best_severity = IncidentSeverity.HIGH
                        best_escalation = EscalationLevel.LEVEL_3
                    elif severity == "medium_keywords" and best_severity not in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
                        best_severity = IncidentSeverity.MEDIUM
                    elif severity == "low_keywords" and best_severity == IncidentSeverity.MEDIUM:
                        best_severity = IncidentSeverity.LOW
        
        return best_category, best_severity, best_escalation


class MitigationEngine:
    """Mitigation action engine"""
    
    def __init__(self):
        self.enabled = os.getenv("MITIGATION_ENGINE_ENABLED", "true").lower() == "true"
        
        # Mitigation strategies
        self.mitigation_strategies = self._load_mitigation_strategies()
        
        # Automated actions
        self.automated_actions = self._load_automated_actions()
        
        self.logger = get_structured_logger("mitigation_engine")
        
        self.logger.info("Mitigation engine initialized", enabled=self.enabled)
    
    def _load_mitigation_strategies(self) -> Dict[IncidentCategory, List[Dict[str, Any]]]:
        """Load mitigation strategies by category"""
        return {
            IncidentCategory.SECURITY_BREACH: [
                {
                    "action": "isolate_affected_systems",
                    "description": "Isolate affected systems from network",
                    "priority": "critical",
                    "automated": False
                },
                {
                    "action": "block_source_ip",
                    "description": "Block source IP address",
                    "priority": "high",
                    "automated": True
                },
                {
                    "action": "notify_security_team",
                    "description": "Notify security team immediately",
                    "priority": "critical",
                    "automated": True
                }
            ],
            IncidentCategory.THREAT_DETECTION: [
                {
                    "action": "monitor_source",
                    "description": "Monitor source IP for additional activity",
                    "priority": "medium",
                    "automated": True
                },
                {
                    "action": "update_threat_intel",
                    "description": "Update threat intelligence with new indicators",
                    "priority": "medium",
                    "automated": True
                }
            ],
            IncidentCategory.PRIVILEGE_ESCALATION: [
                {
                    "action": "revoke_privileges",
                    "description": "Revoke user privileges temporarily",
                    "priority": "high",
                    "automated": True
                },
                {
                    "action": "audit_user_activity",
                    "description": "Audit recent user activity",
                    "priority": "medium",
                    "automated": True
                }
            ],
            IncidentCategory.MALWARE_DETECTION: [
                {
                    "action": "quarantine_system",
                    "description": "Quarantine affected system",
                    "priority": "critical",
                    "automated": True
                },
                {
                    "action": "scan_network",
                    "description": "Scan network for similar threats",
                    "priority": "high",
                    "automated": True
                }
            ],
            IncidentCategory.NETWORK_ATTACK: [
                {
                    "action": "rate_limit_source",
                    "description": "Apply rate limiting to source",
                    "priority": "high",
                    "automated": True
                },
                {
                    "action": "enable_ddos_protection",
                    "description": "Enable enhanced DDoS protection",
                    "priority": "critical",
                    "automated": True
                }
            ]
        }
    
    def _load_automated_actions(self) -> Dict[str, Callable]:
        """Load automated action functions"""
        return {
            "block_source_ip": self._block_source_ip,
            "notify_security_team": self._notify_security_team,
            "monitor_source": self._monitor_source,
            "update_threat_intel": self._update_threat_intel,
            "revoke_privileges": self._revoke_privileges,
            "audit_user_activity": self._audit_user_activity,
            "quarantine_system": self._quarantine_system,
            "scan_network": self._scan_network,
            "rate_limit_source": self._rate_limit_source,
            "enable_ddos_protection": self._enable_ddos_protection
        }
    
    def generate_mitigation_actions(self, incident: Incident) -> List[MitigationAction]:
        """Generate mitigation actions for incident"""
        if not self.enabled:
            return []
        
        actions = []
        strategies = self.mitigation_strategies.get(incident.category, [])
        
        for strategy in strategies:
            action = MitigationAction(
                incident_id=incident.id,
                action_type=strategy["action"],
                description=strategy["description"],
                priority=strategy["priority"],
                automated=strategy["automated"]
            )
            actions.append(action)
        
        return actions
    
    async def execute_mitigation_action(self, action: MitigationAction, incident: Incident) -> bool:
        """Execute mitigation action"""
        if not self.enabled:
            return False
        
        try:
            action.executed_at = datetime.utcnow()
            action.executed_by = "system"
            
            # Execute automated action
            if action.automated and action.action_type in self.automated_actions:
                action_func = self.automated_actions[action.action_type]
                result = await action_func(incident, action)
                action.result = result
                action.success = True
                action.executed = True
                
                self.logger.info(
                    "Mitigation action executed",
                    incident_id=incident.id,
                    action_type=action.action_type,
                    result=result
                )
                
                return True
            else:
                # Manual action - just mark as pending
                action.result = "Manual action required"
                action.executed = True
                
                self.logger.info(
                    "Manual mitigation action created",
                    incident_id=incident.id,
                    action_type=action.action_type
                )
                
                return True
        
        except Exception as e:
            action.result = f"Error: {str(e)}"
            action.success = False
            action.executed = True
            
            self.logger.error(
                "Mitigation action execution failed",
                incident_id=incident.id,
                action_type=action.action_type,
                error=str(e)
            )
            
            return False
    
    async def _block_source_ip(self, incident: Incident, action: MitigationAction) -> str:
        """Block source IP (automated)"""
        if incident.source_ip:
            # In production, integrate with firewall/rate limiting system
            return f"IP {incident.source_ip} blocked for 24 hours"
        return "No source IP to block"
    
    async def _notify_security_team(self, incident: Incident, action: MitigationAction) -> str:
        """Notify security team (automated)"""
        # In production, integrate with notification system
        return f"Security team notified of incident {incident.id}"
    
    async def _monitor_source(self, incident: Incident, action: MitigationAction) -> str:
        """Monitor source (automated)"""
        if incident.source_ip:
            return f"Monitoring IP {incident.source_ip} for additional activity"
        return "No source IP to monitor"
    
    async def _update_threat_intel(self, incident: Incident, action: MitigationAction) -> str:
        """Update threat intelligence (automated)"""
        return f"Threat intelligence updated with indicators from incident {incident.id}"
    
    async def _revoke_privileges(self, incident: Incident, action: MitigationAction) -> str:
        """Revoke privileges (automated)"""
        if incident.user_id:
            return f"Privileges revoked for user {incident.user_id}"
        return "No user ID to revoke privileges"
    
    async def _audit_user_activity(self, incident: Incident, action: MitigationAction) -> str:
        """Audit user activity (automated)"""
        if incident.user_id:
            return f"Auditing activity for user {incident.user_id}"
        return "No user ID to audit"
    
    async def _quarantine_system(self, incident: Incident, action: MitigationAction) -> str:
        """Quarantine system (automated)"""
        return f"System quarantined for incident {incident.id}"
    
    async def _scan_network(self, incident: Incident, action: MitigationAction) -> str:
        """Scan network (automated)"""
        return f"Network scan initiated for incident {incident.id}"
    
    async def _rate_limit_source(self, incident: Incident, action: MitigationAction) -> str:
        """Rate limit source (automated)"""
        if incident.source_ip:
            return f"Rate limiting applied to IP {incident.source_ip}"
        return "No source IP to rate limit"
    
    async def _enable_ddos_protection(self, incident: Incident, action: MitigationAction) -> str:
        """Enable DDoS protection (automated)"""
        return "Enhanced DDoS protection enabled"


class EscalationEngine:
    """Escalation engine for automatic incident escalation"""
    
    def __init__(self):
        self.enabled = os.getenv("ESCALATION_ENGINE_ENABLED", "true").lower() == "true"
        
        # Escalation rules
        self.escalation_rules = self._load_escalation_rules()
        
        # Escalation thresholds
        self.escalation_thresholds = {
            "time_thresholds": {
                EscalationLevel.LEVEL_1: timedelta(minutes=15),
                EscalationLevel.LEVEL_2: timedelta(minutes=30),
                EscalationLevel.LEVEL_3: timedelta(hours=1),
                EscalationLevel.LEVEL_4: timedelta(hours=2)
            },
            "severity_auto_escalate": {
                IncidentSeverity.CRITICAL: EscalationLevel.LEVEL_4,
                IncidentSeverity.HIGH: EscalationLevel.LEVEL_3
            }
        }
        
        self.logger = get_structured_logger("escalation_engine")
        
        self.logger.info("Escalation engine initialized", enabled=self.enabled)
    
    def _load_escalation_rules(self) -> Dict[EscalationLevel, Dict[str, Any]]:
        """Load escalation rules"""
        return {
            EscalationLevel.LEVEL_1: {
                "description": "Automated response",
                "actions": ["automated_mitigation", "monitoring"],
                "notification_channels": ["system_logs"]
            },
            EscalationLevel.LEVEL_2: {
                "description": "Security team notification",
                "actions": ["security_team_alert", "enhanced_monitoring"],
                "notification_channels": ["email", "slack", "system_logs"]
            },
            EscalationLevel.LEVEL_3: {
                "description": "Management notification",
                "actions": ["management_alert", "incident_coordination"],
                "notification_channels": ["email", "slack", "sms", "system_logs"]
            },
            EscalationLevel.LEVEL_4: {
                "description": "Executive notification",
                "actions": ["executive_alert", "emergency_response"],
                "notification_channels": ["email", "slack", "sms", "phone", "system_logs"]
            },
            EscalationLevel.LEVEL_5: {
                "description": "Emergency response",
                "actions": ["emergency_procedures", "external_notification"],
                "notification_channels": ["all_channels", "external_alerts"]
            }
        }
    
    def should_escalate(self, incident: Incident) -> bool:
        """Check if incident should be escalated"""
        if not self.enabled:
            return False
        
        # Auto-escalate based on severity
        if incident.severity in self.escalation_thresholds["severity_auto_escalate"]:
            target_level = self.escalation_thresholds["severity_auto_escalate"][incident.severity]
            if incident.escalation_level.value < target_level.value:
                return True
        
        # Check time-based escalation
        time_threshold = self.escalation_thresholds["time_thresholds"].get(incident.escalation_level)
        if time_threshold and (datetime.utcnow() - incident.created_at) > time_threshold:
            return True
        
        return False
    
    def calculate_escalation_level(self, incident: Incident) -> EscalationLevel:
        """Calculate appropriate escalation level"""
        if not self.enabled:
            return EscalationLevel.LEVEL_1
        
        # Start with current level
        current_level = incident.escalation_level
        
        # Check severity-based escalation
        if incident.severity in self.escalation_thresholds["severity_auto_escalate"]:
            target_level = self.escalation_thresholds["severity_auto_escalate"][incident.severity]
            if target_level.value > current_level.value:
                current_level = target_level
        
        # Check time-based escalation
        time_threshold = self.escalation_thresholds["time_thresholds"].get(current_level)
        if time_threshold and (datetime.utcnow() - incident.created_at) > time_threshold:
            # Move to next level
            levels = list(EscalationLevel)
            current_index = levels.index(current_level)
            if current_index < len(levels) - 1:
                current_level = levels[current_index + 1]
        
        return current_level
    
    async def execute_escalation(self, incident: Incident, new_level: EscalationLevel) -> bool:
        """Execute escalation actions"""
        if not self.enabled:
            return False
        
        try:
            escalation_rule = self.escalation_rules.get(new_level, {})
            actions = escalation_rule.get("actions", [])
            channels = escalation_rule.get("notification_channels", [])
            
            # Execute escalation actions
            for action in actions:
                await self._execute_escalation_action(action, incident)
            
            # Send notifications
            for channel in channels:
                await self._send_notification(channel, incident, new_level)
            
            self.logger.info(
                "Incident escalated",
                incident_id=incident.id,
                from_level=incident.escalation_level.value,
                to_level=new_level.value,
                actions=actions,
                channels=channels
            )
            
            return True
        
        except Exception as e:
            self.logger.error(
                "Escalation execution failed",
                incident_id=incident.id,
                error=str(e)
            )
            return False
    
    async def _execute_escalation_action(self, action: str, incident: Incident):
        """Execute escalation action"""
        # In production, integrate with actual systems
        self.logger.info(f"Executing escalation action: {action} for incident {incident.id}")
    
    async def _send_notification(self, channel: str, incident: Incident, level: EscalationLevel):
        """Send notification"""
        # In production, integrate with notification systems
        self.logger.info(f"Sending {channel} notification for incident {incident.id} at level {level.value}")


class IncidentResponseEngine:
    """Main incident response engine"""
    
    def __init__(self):
        self.enabled = os.getenv("INCIDENT_RESPONSE_ENGINE_ENABLED", "true").lower() == "true"
        
        # Components
        self.classifier = IncidentClassifier()
        self.mitigation_engine = MitigationEngine()
        self.escalation_engine = EscalationEngine()
        
        # Incident storage
        self.incidents: Dict[str, Incident] = {}
        self.incident_events: deque = deque(maxlen=10000)
        
        # Statistics
        self.response_stats = {
            "incidents_created": 0,
            "incidents_resolved": 0,
            "incidents_escalated": 0,
            "mitigations_executed": 0,
            "by_severity": defaultdict(int),
            "by_category": defaultdict(int),
            "by_status": defaultdict(int)
        }
        
        # Event handlers
        self.event_handlers: List[Callable[[Incident], None]] = []
        
        # Background tasks
        self.escalation_task = None
        self.cleanup_task = None
        
        self.logger = get_structured_logger("incident_response_engine")
        
        # Start background tasks
        if self.enabled:
            asyncio.create_task(self.start())
        
        self.logger.info("Incident response engine initialized", enabled=self.enabled)
    
    async def start(self):
        """Start incident response engine"""
        if not self.enabled:
            return
        
        # Start escalation monitoring
        self.escalation_task = asyncio.create_task(self._escalation_monitoring_loop())
        
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_task())
        
        self.logger.info("Incident response engine started")
    
    async def stop(self):
        """Stop incident response engine"""
        if not self.enabled:
            return
        
        # Cancel background tasks
        if self.escalation_task:
            self.escalation_task.cancel()
            try:
                await self.escalation_task
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Incident response engine stopped")
    
    async def create_incident(self, title: str, description: str, source: str,
                            additional_data: Dict[str, Any] = None) -> Incident:
        """Create new incident"""
        if not self.enabled:
            return None
        
        # Classify incident
        category, severity, escalation_level = self.classifier.classify_incident(
            title, description, source, additional_data
        )
        
        # Create incident
        incident = Incident(
            title=title,
            description=description,
            source=source,
            severity=severity,
            category=category,
            escalation_level=escalation_level,
            source_ip=additional_data.get("source_ip") if additional_data else None,
            user_id=additional_data.get("user_id") if additional_data else None,
            session_id=additional_data.get("session_id") if additional_data else None,
            correlation_id=additional_data.get("correlation_id") if additional_data else None,
            evidence=additional_data.get("evidence", {}) if additional_data else {},
            metadata=additional_data.get("metadata", {}) if additional_data else {}
        )
        
        # Store incident
        self.incidents[incident.id] = incident
        self.incident_events.append(incident)
        
        # Update statistics
        self.response_stats["incidents_created"] += 1
        self.response_stats["by_severity"][severity.value] += 1
        self.response_stats["by_category"][category.value] += 1
        self.response_stats["by_status"][incident.status.value] += 1
        
        # Generate mitigation actions
        mitigation_actions = self.mitigation_engine.generate_mitigation_actions(incident)
        incident.mitigation_actions = [action.action_type for action in mitigation_actions]
        
        # Execute automated mitigations
        for action in mitigation_actions:
            if action.automated:
                success = await self.mitigation_engine.execute_mitigation_action(action, incident)
                if success:
                    self.response_stats["mitigations_executed"] += 1
        
        # Notify handlers
        for handler in self.event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(incident)
                else:
                    handler(incident)
            except Exception as e:
                self.logger.error("Incident handler error", handler=str(handler), error=str(e))
        
        self.logger.info(
            "Incident created",
            incident_id=incident.id,
            severity=severity.value,
            category=category.value,
            escalation_level=escalation_level.value
        )
        
        return incident
    
    async def update_incident_status(self, incident_id: str, status: IncidentStatus,
                                   resolution_notes: str = "", assigned_to: str = None) -> bool:
        """Update incident status"""
        if not self.enabled:
            return False
        
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        
        old_status = incident.status
        incident.status = status
        incident.updated_at = datetime.utcnow()
        
        if resolution_notes:
            incident.resolution_notes = resolution_notes
        
        if assigned_to:
            incident.assigned_to = assigned_to
        
        # Update timestamps
        if status == IncidentStatus.RESOLVED:
            incident.resolved_at = datetime.utcnow()
        elif status == IncidentStatus.CLOSED:
            incident.closed_at = datetime.utcnow()
            incident.resolved_at = incident.resolved_at or datetime.utcnow()
        
        # Update statistics
        self.response_stats["by_status"][old_status.value] -= 1
        self.response_stats["by_status"][status.value] += 1
        
        if status == IncidentStatus.RESOLVED:
            self.response_stats["incidents_resolved"] += 1
        
        self.logger.info(
            "Incident status updated",
            incident_id=incident_id,
            old_status=old_status.value,
            new_status=status.value
        )
        
        return True
    
    async def escalate_incident(self, incident_id: str) -> bool:
        """Manually escalate incident"""
        if not self.enabled:
            return False
        
        incident = self.incidents.get(incident_id)
        if not incident:
            return False
        
        # Calculate new escalation level
        new_level = self.escalation_engine.calculate_escalation_level(incident)
        
        if new_level.value > incident.escalation_level.value:
            # Execute escalation
            success = await self.escalation_engine.execute_escalation(incident, new_level)
            
            if success:
                incident.escalation_level = new_level
                incident.status = IncidentStatus.ESCALATED
                incident.updated_at = datetime.utcnow()
                
                self.response_stats["incidents_escalated"] += 1
                
                return True
        
        return False
    
    async def _escalation_monitoring_loop(self):
        """Monitor incidents for automatic escalation"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                for incident in self.incidents.values():
                    if incident.status in [IncidentStatus.NEW, IncidentStatus.INVESTIGATING, IncidentStatus.IDENTIFIED]:
                        if self.escalation_engine.should_escalate(incident):
                            new_level = self.escalation_engine.calculate_escalation_level(incident)
                            
                            if new_level.value > incident.escalation_level.value:
                                success = await self.escalation_engine.execute_escalation(incident, new_level)
                                
                                if success:
                                    incident.escalation_level = new_level
                                    incident.status = IncidentStatus.ESCALATED
                                    incident.updated_at = datetime.utcnow()
                                    
                                    self.response_stats["incidents_escalated"] += 1
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Escalation monitoring error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error
    
    async def _cleanup_task(self):
        """Periodic cleanup task"""
        while True:
            try:
                await asyncio.sleep(3600)  # 1 hour
                
                cutoff_time = datetime.utcnow() - timedelta(days=30)
                
                # Clean up old resolved incidents
                old_incidents = [
                    incident_id for incident_id, incident in self.incidents.items()
                    if incident.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED] 
                    and incident.created_at < cutoff_time
                ]
                
                for incident_id in old_incidents:
                    del self.incidents[incident_id]
                
                if old_incidents:
                    self.logger.info(f"Cleaned up {len(old_incidents)} old incidents")
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Incident cleanup error", error=str(e))
                await asyncio.sleep(300)  # 5 minutes on error
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        return self.incidents.get(incident_id)
    
    def get_incidents(self, limit: int = 100, status: Optional[IncidentStatus] = None,
                     severity: Optional[IncidentSeverity] = None,
                     category: Optional[IncidentCategory] = None) -> List[Incident]:
        """Get incidents with filtering"""
        incidents = list(self.incidents.values())
        
        # Apply filters
        if status:
            incidents = [i for i in incidents if i.status == status]
        
        if severity:
            incidents = [i for i in incidents if i.severity == severity]
        
        if category:
            incidents = [i for i in incidents if i.category == category]
        
        # Sort by timestamp (newest first)
        incidents.sort(key=lambda x: x.created_at, reverse=True)
        
        return incidents[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get incident response statistics"""
        return {
            "enabled": self.enabled,
            **self.response_stats,
            "active_incidents": len(self.incidents),
            "by_severity": dict(self.response_stats["by_severity"]),
            "by_category": dict(self.response_stats["by_category"]),
            "by_status": dict(self.response_stats["by_status"])
        }


# Global incident response engine instance
incident_response_engine = IncidentResponseEngine()


async def start_incident_response():
    """Start incident response engine"""
    await incident_response_engine.start()


async def stop_incident_response():
    """Stop incident response engine"""
    await incident_response_engine.stop()


async def create_incident(title: str, description: str, source: str, **kwargs) -> Incident:
    """Create new incident"""
    return await incident_response_engine.create_incident(title, description, source, kwargs)


async def update_incident_status(incident_id: str, status: str, **kwargs) -> bool:
    """Update incident status"""
    status_enum = IncidentStatus(status)
    return await incident_response_engine.update_incident_status(incident_id, status_enum, **kwargs)


async def escalate_incident(incident_id: str) -> bool:
    """Escalate incident"""
    return await incident_response_engine.escalate_incident(incident_id)


def get_incident_statistics() -> Dict[str, Any]:
    """Get incident response statistics"""
    return incident_response_engine.get_statistics()
