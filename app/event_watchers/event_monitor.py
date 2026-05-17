#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Event Watcher
Windows Event Log monitoring and analysis
"""

import os
import sys
import asyncio
import logging
import json
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
from enum import Enum

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32api
    import winerror
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

# Configure logging
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
            logging.FileHandler(os.path.join(log_dir, 'event_monitor.log')),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)


class EventLogType(Enum):
    """Windows Event Log types"""
    APPLICATION = "Application"
    SYSTEM = "System"
    SECURITY = "Security"
    SETUP = "Setup"
    FORWARDING = "ForwardedEvents"


class EventSeverity(Enum):
    """Event severity levels"""
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFORMATION = "information"
    VERBOSE = "verbose"


class SecurityEventType(Enum):
    """Security event types"""
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    ACCOUNT_LOCKOUT = "account_lockout"
    PRIVILEGE_USE = "privilege_use"
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    OBJECT_ACCESS = "object_access"
    POLICY_CHANGE = "policy_change"
    SPECIAL_PRIVILEGE = "special_privilege"
    INTEGRITY_CHANGE = "integrity_change"


@dataclass
class WindowsEvent:
    """Windows Event data structure"""
    event_id: int
    timestamp: datetime
    source: str
    event_type: EventLogType
    severity: EventSeverity
    computer: str
    user: Optional[str]
    description: str
    data: Dict[str, Any]
    raw_data: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'computer': self.computer,
            'user': self.user,
            'description': self.description,
            'data': self.data,
            'raw_data': self.raw_data
        }


@dataclass
class SecurityAlert:
    """Security alert data structure"""
    alert_id: str
    timestamp: datetime
    alert_type: SecurityEventType
    severity: EventSeverity
    description: str
    evidence: Dict[str, Any]
    confidence: float
    event_ids: List[int]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'event_ids': self.event_ids
        }


class EventMonitor:
    """Windows Event Log monitor"""
    
    def __init__(self):
        """Initialize event monitor"""
        self.is_running = False
        self.events: deque = deque(maxlen=10000)
        self.security_alerts: deque = deque(maxlen=1000)
        self.event_callbacks: List[Callable] = []
        
        # Event log handles
        self.log_handles: Dict[EventLogType, Any] = {}
        
        # Configuration
        self.config = {
            'monitored_logs': [EventLogType.SECURITY, EventLogType.SYSTEM, EventLogType.APPLICATION],
            'real_time_monitoring': True,
            'max_events_per_minute': 100,
            'alert_threshold': 0.7,
            'enable_correlation': True,
            'correlation_window': 300  # seconds
        }
        
        # Event patterns and signatures
        self.security_event_patterns = self._initialize_security_patterns()
        self.suspicious_patterns = self._initialize_suspicious_patterns()
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'security_alerts': 0,
            'events_by_type': defaultdict(int),
            'events_by_severity': defaultdict(int),
            'start_time': None
        }
        
        logger.info("Event monitor initialized")
    
    def _initialize_security_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize security event patterns"""
        return {
            'failed_login': [
                {
                    'event_id': 4625,
                    'description': 'An account failed to log on',
                    'severity': EventSeverity.WARNING,
                    'pattern': r'Failure Reason:\s*(.*)',
                    'confidence': 0.9
                },
                {
                    'event_id': 4624,
                    'description': 'An account was successfully logged on',
                    'severity': EventSeverity.INFORMATION,
                    'pattern': r'Logon Type:\s*(\d+)',
                    'confidence': 0.8
                }
            ],
            'account_lockout': [
                {
                    'event_id': 4740,
                    'description': 'A user account was locked out',
                    'severity': EventSeverity.WARNING,
                    'pattern': r'Target Account Name:\s*(.*)',
                    'confidence': 0.95
                }
            ],
            'process_creation': [
                {
                    'event_id': 4688,
                    'description': 'A new process has been created',
                    'severity': EventSeverity.INFORMATION,
                    'pattern': r'Process Name:\s*(.*)',
                    'confidence': 0.7
                }
            ],
            'privilege_use': [
                {
                    'event_id': 4672,
                    'description': 'Special privileges assigned to new logon',
                    'severity': EventSeverity.WARNING,
                    'pattern': r'Privilege List:\s*(.*)',
                    'confidence': 0.8
                }
            ],
            'network_connection': [
                {
                    'event_id': 5156,
                    'description': 'The Windows Filtering Platform has permitted a connection',
                    'severity': EventSeverity.INFORMATION,
                    'pattern': r'Direction:\s*(.*)',
                    'confidence': 0.6
                }
            ],
            'object_access': [
                {
                    'event_id': 4663,
                    'description': 'An attempt was made to access an object',
                    'severity': EventSeverity.WARNING,
                    'pattern': r'Object Name:\s*(.*)',
                    'confidence': 0.7
                }
            ],
            'policy_change': [
                {
                    'event_id': 4719,
                    'description': 'System audit policy was changed',
                    'severity': EventSeverity.WARNING,
                    'pattern': r'Category:\s*(.*)',
                    'confidence': 0.8
                }
            ]
        }
    
    def _initialize_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """Initialize suspicious event patterns"""
        return [
            {
                'name': 'multiple_failed_logins',
                'description': 'Multiple failed login attempts',
                'pattern': 'failed_login',
                'threshold': 5,
                'time_window': 300,
                'severity': EventSeverity.WARNING,
                'confidence': 0.8
            },
            {
                'name': 'privilege_escalation',
                'description': 'Privilege escalation detected',
                'pattern': 'privilege_use',
                'threshold': 3,
                'time_window': 600,
                'severity': EventSeverity.ERROR,
                'confidence': 0.9
            },
            {
                'name': 'unusual_process_creation',
                'description': 'Unusual process creation pattern',
                'pattern': 'process_creation',
                'threshold': 10,
                'time_window': 300,
                'severity': EventSeverity.WARNING,
                'confidence': 0.7
            },
            {
                'name': 'suspicious_network_activity',
                'description': 'Suspicious network activity',
                'pattern': 'network_connection',
                'threshold': 20,
                'time_window': 300,
                'severity': EventSeverity.WARNING,
                'confidence': 0.6
            }
        ]
    
    async def start(self):
        """Start event monitoring"""
        try:
            logger.info("Starting event monitor")
            
            if not WINDOWS_AVAILABLE:
                logger.warning("Windows Event Log modules not available - running in simulation mode")
            
            self.is_running = True
            self.stats['start_time'] = datetime.utcnow()
            
            # Open event log handles
            if WINDOWS_AVAILABLE:
                await self._open_event_logs()
            
            # Start monitoring
            asyncio.create_task(self._monitor_events())
            
            # Start correlation analysis
            if self.config['enable_correlation']:
                asyncio.create_task(self._correlation_analysis())
            
            logger.info("Event monitor started successfully")
            
        except Exception as e:
            logger.error(f"Error starting event monitor: {e}")
            raise
    
    async def stop(self):
        """Stop event monitoring"""
        try:
            logger.info("Stopping event monitor")
            
            self.is_running = False
            
            # Close event log handles
            if WINDOWS_AVAILABLE:
                await self._close_event_logs()
            
            logger.info("Event monitor stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping event monitor: {e}")
    
    async def _open_event_logs(self):
        """Open Windows Event Log handles"""
        try:
            for log_type in self.config['monitored_logs']:
                try:
                    handle = win32evtlog.OpenEventLog(None, log_type.value)
                    self.log_handles[log_type] = handle
                    logger.info(f"Opened event log: {log_type.value}")
                except Exception as e:
                    logger.error(f"Error opening event log {log_type.value}: {e}")
                    
        except Exception as e:
            logger.error(f"Error opening event logs: {e}")
    
    async def _close_event_logs(self):
        """Close Windows Event Log handles"""
        try:
            for log_type, handle in self.log_handles.items():
                try:
                    win32evtlog.CloseEventLog(handle)
                    logger.info(f"Closed event log: {log_type.value}")
                except Exception as e:
                    logger.error(f"Error closing event log {log_type.value}: {e}")
            
            self.log_handles.clear()
            
        except Exception as e:
            logger.error(f"Error closing event logs: {e}")
    
    async def _monitor_events(self):
        """Monitor Windows Event Logs"""
        try:
            while self.is_running:
                try:
                    if WINDOWS_AVAILABLE:
                        await self._read_windows_events()
                    else:
                        await self._simulate_events()
                    
                    await asyncio.sleep(5)  # Check every 5 seconds
                    
                except Exception as e:
                    logger.error(f"Error in event monitoring: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            logger.error(f"Event monitoring error: {e}")
    
    async def _read_windows_events(self):
        """Read events from Windows Event Logs"""
        try:
            for log_type, handle in self.log_handles.items():
                try:
                    # Read events from log
                    events = win32evtlog.ReadEventLog(handle, win32evtlog.EVENTLOG_BACKWARDS_READ | 
                                                   win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
                    
                    if not events:
                        continue
                    
                    for event in events:
                        try:
                            windows_event = await self._parse_windows_event(event, log_type)
                            if windows_event:
                                await self._process_event(windows_event)
                        except Exception as e:
                            logger.error(f"Error parsing event: {e}")
                            
                except Exception as e:
                    # No new events or error
                    continue
                    
        except Exception as e:
            logger.error(f"Error reading Windows events: {e}")
    
    async def _parse_windows_event(self, event, log_type: EventLogType) -> Optional[WindowsEvent]:
        """Parse Windows Event"""
        try:
            # Extract event information
            event_id = event.EventID & 0xFFFF  # Remove qualifier
            timestamp = datetime.fromtimestamp(event.TimeGenerated.timestamp())
            source = event.SourceName
            computer = event.ComputerName
            
            # Determine severity
            if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
                severity = EventSeverity.ERROR
            elif event.EventType == win32evtlog.EVENTLOG_WARNING_TYPE:
                severity = EventSeverity.WARNING
            elif event.EventType == win32evtlog.EVENTLOG_INFORMATION_TYPE:
                severity = EventSeverity.INFORMATION
            else:
                severity = EventSeverity.VERBOSE
            
            # Extract description and data
            description = win32evtlogutil.SafeFormatMessage(event)
            
            # Parse event data
            data = {
                'event_category': event.EventCategory,
                'event_type': event.EventType,
                'strings': event.StringInserts if event.StringInserts else []
            }
            
            # Extract user information
            user = None
            if hasattr(event, 'Sid') and event.Sid:
                try:
                    account_name, domain, _ = win32security.LookupAccountSid(None, event.Sid)
                    user = f"{domain}\\{account_name}"
                except:
                    user = "Unknown"
            
            # Create Windows event
            windows_event = WindowsEvent(
                event_id=event_id,
                timestamp=timestamp,
                source=source,
                event_type=log_type,
                severity=severity,
                computer=computer,
                user=user,
                description=description,
                data=data,
                raw_data=str(event)
            )
            
            return windows_event
            
        except Exception as e:
            logger.error(f"Error parsing Windows event: {e}")
            return None
    
    async def _simulate_events(self):
        """Simulate events for non-Windows systems"""
        try:
            # Simulate security events
            if random.random() < 0.1:  # 10% chance
                event_types = [
                    (4625, "Failed login attempt", EventSeverity.WARNING),
                    (4624, "Successful login", EventSeverity.INFORMATION),
                    (4740, "Account locked out", EventSeverity.WARNING),
                    (4688, "Process created", EventSeverity.INFORMATION),
                    (4672, "Special privileges assigned", EventSeverity.WARNING)
                ]
                
                event_id, desc, severity = random.choice(event_types)
                
                simulated_event = WindowsEvent(
                    event_id=event_id,
                    timestamp=datetime.utcnow(),
                    source="Security",
                    event_type=EventLogType.SECURITY,
                    severity=severity,
                    computer="SIMULATION-PC",
                    user=random.choice(["admin", "user1", "user2"]),
                    description=desc,
                    data={'simulation': True},
                    raw_data=None
                )
                
                await self._process_event(simulated_event)
                
        except Exception as e:
            logger.error(f"Error simulating events: {e}")
    
    async def _process_event(self, event: WindowsEvent):
        """Process Windows event"""
        try:
            # Store event
            self.events.append(event)
            self.stats['total_events'] += 1
            self.stats['events_by_type'][event.event_type.value] += 1
            self.stats['events_by_severity'][event.severity.value] += 1
            
            # Analyze for security threats
            if event.event_type == EventLogType.SECURITY:
                await self._analyze_security_event(event)
            
            # Notify callbacks
            for callback in self.event_callbacks:
                try:
                    await callback(event)
                except Exception as e:
                    logger.error(f"Error in event callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    async def _analyze_security_event(self, event: WindowsEvent):
        """Analyze security event for threats"""
        try:
            # Check against security patterns
            for alert_type, patterns in self.security_event_patterns.items():
                for pattern in patterns:
                    if event.event_id == pattern['event_id']:
                        # Extract evidence using regex
                        evidence = {}
                        if 'pattern' in pattern:
                            match = re.search(pattern['pattern'], event.description, re.IGNORECASE)
                            if match:
                                evidence['match'] = match.group(1) if match.groups() else match.group(0)
                        
                        # Create security alert
                        alert = SecurityAlert(
                            alert_id=str(uuid.uuid4()),
                            timestamp=event.timestamp,
                            alert_type=SecurityEventType(alert_type),
                            severity=pattern['severity'],
                            description=f"{pattern['description']}: {event.description[:100]}",
                            evidence=evidence,
                            confidence=pattern['confidence'],
                            event_ids=[event.event_id]
                        )
                        
                        self.security_alerts.append(alert)
                        self.stats['security_alerts'] += 1
                        
                        logger.warning(f"Security alert: {alert.description}")
                        
        except Exception as e:
            logger.error(f"Error analyzing security event: {e}")
    
    async def _correlation_analysis(self):
        """Perform event correlation analysis"""
        try:
            while self.is_running:
                try:
                    if self.config['enable_correlation']:
                        await self._analyze_event_patterns()
                    
                    await asyncio.sleep(60)  # Analyze every minute
                    
                except Exception as e:
                    logger.error(f"Error in correlation analysis: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            logger.error(f"Correlation analysis error: {e}")
    
    async def _analyze_event_patterns(self):
        """Analyze event patterns for suspicious activity"""
        try:
            current_time = datetime.utcnow()
            
            for pattern in self.suspicious_patterns:
                # Get recent events of the pattern type
                recent_events = [
                    event for event in self.events
                    if (current_time - event.timestamp).total_seconds() <= pattern['time_window']
                    and self._matches_pattern(event, pattern['pattern'])
                ]
                
                # Check if threshold is exceeded
                if len(recent_events) >= pattern['threshold']:
                    # Create correlated alert
                    alert = SecurityAlert(
                        alert_id=str(uuid.uuid4()),
                        timestamp=current_time,
                        alert_type=SecurityEventType.MULTIPLE_FAILED_LOGINS,  # Generic type
                        severity=pattern['severity'],
                        description=f"{pattern['description']}: {len(recent_events)} events in {pattern['time_window']}s",
                        evidence={
                            'pattern_name': pattern['name'],
                            'event_count': len(recent_events),
                            'time_window': pattern['time_window'],
                            'threshold': pattern['threshold'],
                            'event_ids': [event.event_id for event in recent_events]
                        },
                        confidence=pattern['confidence'],
                        event_ids=[event.event_id for event in recent_events]
                    )
                    
                    self.security_alerts.append(alert)
                    self.stats['security_alerts'] += 1
                    
                    logger.warning(f"Correlated security alert: {alert.description}")
                    
        except Exception as e:
            logger.error(f"Error analyzing event patterns: {e}")
    
    def _matches_pattern(self, event: WindowsEvent, pattern_type: str) -> bool:
        """Check if event matches pattern type"""
        try:
            if pattern_type == 'failed_login':
                return event.event_id == 4625
            elif pattern_type == 'privilege_use':
                return event.event_id == 4672
            elif pattern_type == 'process_creation':
                return event.event_id == 4688
            elif pattern_type == 'network_connection':
                return event.event_id == 5156
            else:
                return False
                
        except Exception:
            return False
    
    def add_event_callback(self, callback: Callable):
        """Add event callback"""
        self.event_callbacks.append(callback)
    
    def get_events(self, log_type: Optional[EventLogType] = None, 
                  severity: Optional[EventSeverity] = None,
                  limit: int = 100) -> List[Dict[str, Any]]:
        """Get events with filters"""
        try:
            events = list(self.events)
            
            # Apply filters
            if log_type:
                events = [e for e in events if e.event_type == log_type]
            
            if severity:
                events = [e for e in events if e.severity == severity]
            
            # Sort by timestamp (most recent first)
            events.sort(key=lambda x: x.timestamp, reverse=True)
            
            return [event.to_dict() for event in events[:limit]]
            
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return []
    
    def get_security_alerts(self, alert_type: Optional[SecurityEventType] = None,
                           severity: Optional[EventSeverity] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """Get security alerts with filters"""
        try:
            alerts = list(self.security_alerts)
            
            # Apply filters
            if alert_type:
                alerts = [a for a in alerts if a.alert_type == alert_type]
            
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            # Sort by timestamp (most recent first)
            alerts.sort(key=lambda x: x.timestamp, reverse=True)
            
            return [alert.to_dict() for alert in alerts[:limit]]
            
        except Exception as e:
            logger.error(f"Error getting security alerts: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        try:
            uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0
            
            return {
                'is_running': self.is_running,
                'uptime': uptime,
                'total_events': self.stats['total_events'],
                'security_alerts': self.stats['security_alerts'],
                'events_by_type': dict(self.stats['events_by_type']),
                'events_by_severity': dict(self.stats['events_by_severity']),
                'monitored_logs': [log.value for log in self.config['monitored_logs']],
                'config': self.config
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {'error': str(e)}


# Global event monitor instance
event_monitor = EventMonitor()


# API functions
async def start_event_monitor() -> str:
    """Start event monitor"""
    try:
        await event_monitor.start()
        logger.info("Event monitor started")
        return "Event monitor started successfully"
    except Exception as e:
        logger.error(f"Error starting event monitor: {e}")
        return f"Error starting event monitor: {e}"


async def stop_event_monitor() -> str:
    """Stop event monitor"""
    try:
        await event_monitor.stop()
        logger.info("Event monitor stopped")
        return "Event monitor stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping event monitor: {e}")
        return f"Error stopping event monitor: {e}"


def get_events(log_type: Optional[str] = None, severity: Optional[str] = None, 
               limit: int = 100) -> List[Dict[str, Any]]:
    """Get events with filters"""
    try:
        # Convert string parameters to enums
        log_type_enum = EventLogType(log_type) if log_type else None
        severity_enum = EventSeverity(severity) if severity else None
        
        return event_monitor.get_events(log_type_enum, severity_enum, limit)
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return []


def get_security_alerts(alert_type: Optional[str] = None, severity: Optional[str] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
    """Get security alerts with filters"""
    try:
        # Convert string parameters to enums
        alert_type_enum = SecurityEventType(alert_type) if alert_type else None
        severity_enum = EventSeverity(severity) if severity else None
        
        return event_monitor.get_security_alerts(alert_type_enum, severity_enum, limit)
    except Exception as e:
        logger.error(f"Error getting security alerts: {e}")
        return []


def get_event_statistics() -> Dict[str, Any]:
    """Get event monitor statistics"""
    try:
        return event_monitor.get_statistics()
    except Exception as e:
        logger.error(f"Error getting event statistics: {e}")
        return {'error': str(e)}


def add_event_callback(callback: Callable):
    """Add event callback"""
    try:
        event_monitor.add_event_callback(callback)
        logger.info("Event callback added")
    except Exception as e:
        logger.error(f"Error adding event callback: {e}"


# Initialize event monitor
async def initialize_event_monitor() -> str:
    """Initialize event monitor"""
    try:
        await start_event_monitor()
        logger.info("Event monitor initialized")
        return "Event monitor initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing event monitor: {e}")
        return f"Error initializing event monitor: {e}"


# Cleanup function
async def cleanup_event_monitor() -> str:
    """Cleanup event monitor"""
    try:
        await stop_event_monitor()
        logger.info("Event monitor cleaned up")
        return "Event monitor cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up event monitor: {e}")
        return f"Error cleaning up event monitor: {e}"
