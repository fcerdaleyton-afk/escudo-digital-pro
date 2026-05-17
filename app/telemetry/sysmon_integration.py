#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Sysmon Integration
Windows Sysmon events integration into telemetry engine
"""

import os
import sys
import asyncio
import logging
import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict

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
            logging.FileHandler(os.path.join(log_dir, 'sysmon_integration.log')),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32api
    import win32file
    import win32pipe
    import pywintypes
    import subprocess
    import psutil
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    logger.warning("Windows-specific modules not available - using simulation mode")


class SysmonEventType(Enum):
    """Sysmon event types"""
    PROCESS_CREATE = 1
    FILE_CREATE = 2
    NETWORK_CONNECT = 3
    PROCESS_TERMINATE = 5
    DRIVER_LOAD = 6
    IMAGE_LOAD = 7
    CREATE_REMOTE_THREAD = 8
    PROCESS_ACCESS = 10
    FILE_CREATE_STREAM_HASH = 15
    REGISTRY_CREATE = 12
    REGISTRY_DELETE = 13
    REGISTRY_SET = 14
    PROCESS_CREATE_GUID = 1
    FILE_CREATE_GUID = 2
    NETWORK_CONNECT_GUID = 3
    PIPE_EVENT = 18
    WMI_EVENT = 19


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SysmonEvent:
    """Sysmon event data structure"""
    event_id: str
    timestamp: datetime
    event_type: SysmonEventType
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    computer_name: Optional[str] = None
    image_path: Optional[str] = None
    file_path: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    network_protocol: Optional[str] = None
    hash_value: Optional[str] = None
    severity: ThreatSeverity = ThreatSeverity.LOW
    threat_indicators: List[str] = None
    raw_data: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'process_id': self.process_id,
            'process_name': self.process_name,
            'parent_process_id': self.parent_process_id,
            'parent_process_name': self.parent_process_name,
            'command_line': self.command_line,
            'user': self.user,
            'computer_name': self.computer_name,
            'image_path': self.image_path,
            'file_path': self.file_path,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'network_protocol': self.network_protocol,
            'hash_value': self.hash_value,
            'severity': self.severity.value,
            'threat_indicators': self.threat_indicators or [],
            'raw_data': self.raw_data or {}
        }


class SysmonIntegration:
    """Sysmon events integration into telemetry engine"""
    
    def __init__(self):
        """Initialize Sysmon integration"""
        self.is_running = False
        self.event_callbacks: List[Callable] = []
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.processed_events: Dict[str, SysmonEvent] = {}
        self.threat_patterns = self._get_threat_patterns()
        
        # Configuration
        self.config = {
            'sysmon_log_name': 'Microsoft-Windows-Sysmon/Operational',
            'max_queue_size': 10000,
            'processing_interval': 5,  # seconds
            'event_retention_hours': 24,
            'enable_process_monitoring': True,
            'enable_network_monitoring': True,
            'enable_encoding_detection': True,
            'enable_parent_child_analysis': True
        }
        
        logger.info("Sysmon integration initialized")
    
    def _get_threat_patterns(self) -> Dict[str, List[str]]:
        """Get threat detection patterns"""
        return {
            'encoded_powershell': [
                r'-enc\s+',
                r'-encodedcommand\s+',
                r'-e\s+\w+',
                r'FromBase64String',
                r'ConvertTo-SecureString',
                r'IEX\s+',
                r'Invoke-Expression',
                r'Start-job\s+.*-scriptblock',
                r'Get-Acl\s+.*\|.*Set-Acl',
                r'New-Object\s+System\.Text\.UTF8Encoding'
            ],
            'suspicious_processes': [
                'powershell.exe',
                'cmd.exe',
                'wscript.exe',
                'cscript.exe',
                'rundll32.exe',
                'regsvr32.exe',
                'mshta.exe',
                'certutil.exe',
                'bitsadmin.exe',
                'wmic.exe',
                'net.exe',
                'netsh.exe',
                'tasklist.exe',
                'whoami.exe',
                'nltest.exe',
                'nslookup.exe',
                'ping.exe'
            ],
            'suspicious_command_lines': [
                r'powershell.*-enc',
                r'cmd.*\/c.*echo.*>',
                r'certutil.*-urlcache.*split',
                r'bitsadmin.*\/transfer.*download',
                r'wmic.*process.*call.*create',
                r'net.*user.*\/add',
                r'net.*localgroup.*\/add',
                r'reg.*add.*\/f',
                r'schtasks.*\/create.*\/ru.*system'
            ],
            'suspicious_network_ports': [
                4444, 5555, 6667, 8080, 9999, 31337, 12345, 54321, 4433
            ],
            'suspicious_parent_child': [
                ('winword.exe', 'powershell.exe'),
                ('excel.exe', 'cmd.exe'),
                ('powershell.exe', 'rundll32.exe'),
                ('explorer.exe', 'wscript.exe'),
                ('svchost.exe', 'cmd.exe'),
                ('lsass.exe', 'powershell.exe'),
                ('winlogon.exe', 'net.exe')
            ]
        }
    
    async def start(self):
        """Start Sysmon integration"""
        try:
            logger.info("Starting Sysmon integration")
            
            self.is_running = True
            
            # Start background tasks
            asyncio.create_task(self._monitor_sysmon_events())
            asyncio.create_task(self._process_event_queue())
            asyncio.create_task(self._cleanup_old_events())
            
            logger.info("Sysmon integration started successfully")
            
        except Exception as e:
            logger.error(f"Error starting Sysmon integration: {e}")
            raise
    
    async def stop(self):
        """Stop Sysmon integration"""
        try:
            logger.info("Stopping Sysmon integration")
            
            self.is_running = False
            
            logger.info("Sysmon integration stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping Sysmon integration: {e}")
    
    def add_event_callback(self, callback: Callable):
        """Add event callback"""
        self.event_callbacks.append(callback)
        logger.info(f"Event callback added (total: {len(self.event_callbacks)})")
    
    def remove_event_callback(self, callback: Callable):
        """Remove event callback"""
        if callback in self.event_callbacks:
            self.event_callbacks.remove(callback)
            logger.info(f"Event callback removed (total: {len(self.event_callbacks)})")
    
    async def _monitor_sysmon_events(self):
        """Monitor Sysmon events"""
        try:
            while self.is_running:
                try:
                    if WINDOWS_AVAILABLE:
                        events = self._read_sysmon_events()
                        for event in events:
                            await self.event_queue.put(event)
                    else:
                        # Simulation mode
                        await self._simulate_events()
                    
                    await asyncio.sleep(self.config['processing_interval'])
                    
                except Exception as e:
                    logger.error(f"Error monitoring Sysmon events: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            logger.error(f"Sysmon monitoring error: {e}")
    
    def _read_sysmon_events(self) -> List[SysmonEvent]:
        """Read Sysmon events from Windows Event Log"""
        try:
            events = []
            
            # Open Sysmon event log
            handle = win32evtlog.OpenEventLog(
                None,
                self.config['sysmon_log_name']
            )
            
            # Read events
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total_events = win32evtlog.GetNumberOfEventLogRecords(handle)
            
            # Read last 100 events to avoid processing old events
            events_to_read = min(100, total_events)
            
            for i in range(events_to_read):
                event_data = win32evtlog.ReadEventLog(handle, flags)
                
                if event_data:
                    sysmon_event = self._parse_sysmon_event(event_data)
                    if sysmon_event:
                        events.append(sysmon_event)
            
            win32evtlog.CloseEventLog(handle)
            
            return events
            
        except Exception as e:
            logger.error(f"Error reading Sysmon events: {e}")
            return []
    
    def _parse_sysmon_event(self, event_data) -> Optional[SysmonEvent]:
        """Parse Sysmon event data"""
        try:
            # Extract basic event information
            event_id = str(uuid.uuid4())
            timestamp = event_data.TimeGenerated
            event_type = SysmonEventType(event_data.EventID)
            
            # Parse XML data
            xml_data = event_data.StringInserts[0] if event_data.StringInserts else ""
            if xml_data:
                root = ET.fromstring(xml_data)
                
                # Extract event-specific data
                sysmon_event = SysmonEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    event_type=event_type
                )
                
                # Common fields
                sysmon_event.computer_name = root.get('Computer')
                sysmon_event.user = root.get('SecurityUserID')
                
                # Parse based on event type
                if event_type == SysmonEventType.PROCESS_CREATE:
                    self._parse_process_create(root, sysmon_event)
                elif event_type == SysmonEventType.NETWORK_CONNECT:
                    self._parse_network_connect(root, sysmon_event)
                elif event_type == SysmonEventType.FILE_CREATE:
                    self._parse_file_create(root, sysmon_event)
                
                # Analyze for threats
                self._analyze_threat_indicators(sysmon_event)
                
                return sysmon_event
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing Sysmon event: {e}")
            return None
    
    def _parse_process_create(self, root: ET.Element, event: SysmonEvent):
        """Parse process creation event"""
        try:
            data = root.find('Data')
            
            for item in data.findall('Data'):
                name = item.get('Name')
                value = item.text
                
                if name == 'ProcessId':
                    event.process_id = int(value) if value else None
                elif name == 'Image':
                    event.image_path = value
                    event.process_name = os.path.basename(value) if value else None
                elif name == 'CommandLine':
                    event.command_line = value
                elif name == 'ParentProcessId':
                    event.parent_process_id = int(value) if value else None
                elif name == 'ParentImage':
                    event.parent_process_name = os.path.basename(value) if value else None
                    
        except Exception as e:
            logger.error(f"Error parsing process creation: {e}")
    
    def _parse_network_connect(self, root: ET.Element, event: SysmonEvent):
        """Parse network connection event"""
        try:
            data = root.find('Data')
            
            for item in data.findall('Data'):
                name = item.get('Name')
                value = item.text
                
                if name == 'ProcessId':
                    event.process_id = int(value) if value else None
                elif name == 'Image':
                    event.image_path = value
                    event.process_name = os.path.basename(value) if value else None
                elif name == 'DestinationIp':
                    event.destination_ip = value
                elif name == 'DestinationPort':
                    event.destination_port = int(value) if value else None
                elif name == 'SourceIp':
                    event.source_ip = value
                elif name == 'SourcePort':
                    event.source_port = int(value) if value else None
                elif name == 'Protocol':
                    event.network_protocol = value
                    
        except Exception as e:
            logger.error(f"Error parsing network connect: {e}")
    
    def _parse_file_create(self, root: ET.Element, event: SysmonEvent):
        """Parse file creation event"""
        try:
            data = root.find('Data')
            
            for item in data.findall('Data'):
                name = item.get('Name')
                value = item.text
                
                if name == 'ProcessId':
                    event.process_id = int(value) if value else None
                elif name == 'Image':
                    event.image_path = value
                    event.process_name = os.path.basename(value) if value else None
                elif name == 'FileName':
                    event.file_path = value
                elif name == 'Hashes':
                    # Parse hash values
                    if value:
                        hash_parts = value.split(',')
                        for part in hash_parts:
                            if 'SHA1=' in part:
                                event.hash_value = part.split('=')[1]
                                break
                                
        except Exception as e:
            logger.error(f"Error parsing file create: {e}")
    
    def _analyze_threat_indicators(self, event: SysmonEvent):
        """Analyze event for threat indicators"""
        try:
            import re
            
            threat_indicators = []
            
            # Check for encoded PowerShell
            if event.command_line and self.config['enable_encoding_detection']:
                for pattern in self.threat_patterns['encoded_powershell']:
                    if re.search(pattern, event.command_line, re.IGNORECASE):
                        threat_indicators.append('encoded_powershell')
                        event.severity = max(event.severity, ThreatSeverity.HIGH, key=lambda x: list(ThreatSeverity).index(x))
                        break
            
            # Check for suspicious processes
            if event.process_name and self.config['enable_process_monitoring']:
                if event.process_name.lower() in [p.lower() for p in self.threat_patterns['suspicious_processes']]:
                    threat_indicators.append('suspicious_process')
                    event.severity = max(event.severity, ThreatSeverity.MEDIUM, key=lambda x: list(ThreatSeverity).index(x))
            
            # Check for suspicious command lines
            if event.command_line and self.config['enable_encoding_detection']:
                for pattern in self.threat_patterns['suspicious_command_lines']:
                    if re.search(pattern, event.command_line, re.IGNORECASE):
                        threat_indicators.append('suspicious_command')
                        event.severity = max(event.severity, ThreatSeverity.HIGH, key=lambda x: list(ThreatSeverity).index(x))
                        break
            
            # Check for suspicious network connections
            if event.destination_port and self.config['enable_network_monitoring']:
                if event.destination_port in self.threat_patterns['suspicious_network_ports']:
                    threat_indicators.append('suspicious_port')
                    event.severity = max(event.severity, ThreatSeverity.MEDIUM, key=lambda x: list(ThreatSeverity).index(x))
            
            # Check for suspicious parent-child relationships
            if (event.parent_process_name and event.process_name and 
                self.config['enable_parent_child_analysis']):
                for parent, child in self.threat_patterns['suspicious_parent_child']:
                    if (event.parent_process_name.lower() == parent.lower() and 
                        event.process_name.lower() == child.lower()):
                        threat_indicators.append('suspicious_parent_child')
                        event.severity = max(event.severity, ThreatSeverity.HIGH, key=lambda x: list(ThreatSeverity).index(x))
                        break
            
            event.threat_indicators = threat_indicators
            
        except Exception as e:
            logger.error(f"Error analyzing threat indicators: {e}")
    
    async def _simulate_events(self):
        """Simulate events for testing"""
        if not WINDOWS_AVAILABLE:
            # Generate simulated events
            import random
            
            if random.random() < 0.1:  # 10% chance
                event = SysmonEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow(),
                    event_type=random.choice([SysmonEventType.PROCESS_CREATE, SysmonEventType.NETWORK_CONNECT]),
                    process_id=random.randint(1000, 9999),
                    process_name="simulated_process.exe",
                    parent_process_id=random.randint(1, 999),
                    parent_process_name="simulated_parent.exe",
                    command_line="simulated_command -test",
                    user="SIMULATION\\User",
                    computer_name="SIMULATION-PC",
                    severity=ThreatSeverity.LOW,
                    threat_indicators=['simulation']
                )
                
                await self.event_queue.put(event)
    
    async def _process_event_queue(self):
        """Process event queue"""
        try:
            while self.is_running:
                try:
                    # Get event from queue
                    event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                    
                    # Store event
                    self.processed_events[event.event_id] = event
                    
                    # Forward to callbacks
                    for callback in self.event_callbacks:
                        try:
                            await callback({
                                'type': 'sysmon_event',
                                'data': event.to_dict()
                            })
                        except Exception as e:
                            logger.error(f"Error in event callback: {e}")
                    
                    logger.debug(f"Processed Sysmon event: {event.event_type.value} - {event.process_name}")
                    
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing event queue: {e}")
                    
        except Exception as e:
            logger.error(f"Event queue processing error: {e}")
    
    async def _cleanup_old_events(self):
        """Cleanup old events"""
        try:
            while self.is_running:
                # Cleanup every hour
                await asyncio.sleep(3600)
                
                cutoff_time = datetime.utcnow() - timedelta(hours=self.config['event_retention_hours'])
                
                # Remove old events
                old_events = [
                    event_id for event_id, event in self.processed_events.items()
                    if event.timestamp < cutoff_time
                ]
                
                for event_id in old_events:
                    del self.processed_events[event_id]
                    
                if old_events:
                    logger.info(f"Cleaned up {len(old_events)} old Sysmon events")
                    
        except Exception as e:
            logger.error(f"Event cleanup error: {e}")
    
    def get_events(self, limit: int = 100, event_type: Optional[SysmonEventType] = None) -> List[Dict[str, Any]]:
        """Get processed events"""
        try:
            events = list(self.processed_events.values())
            
            # Filter by event type
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            
            # Sort by timestamp (most recent first)
            events.sort(key=lambda x: x.timestamp, reverse=True)
            
            # Limit results
            events = events[:limit]
            
            return [event.to_dict() for event in events]
            
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Sysmon integration statistics"""
        try:
            total_events = len(self.processed_events)
            
            # Count by event type
            event_type_counts = defaultdict(int)
            for event in self.processed_events.values():
                event_type_counts[event.event_type.value] += 1
            
            # Count by severity
            severity_counts = defaultdict(int)
            for event in self.processed_events.values():
                severity_counts[event.severity.value] += 1
            
            # Count by threat indicators
            indicator_counts = defaultdict(int)
            for event in self.processed_events.values():
                for indicator in event.threat_indicators or []:
                    indicator_counts[indicator] += 1
            
            return {
                'total_events': total_events,
                'event_type_distribution': dict(event_type_counts),
                'severity_distribution': dict(severity_counts),
                'threat_indicators': dict(indicator_counts),
                'queue_size': self.event_queue.qsize(),
                'is_running': self.is_running,
                'windows_available': WINDOWS_AVAILABLE,
                'config': self.config
            }
            
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {'error': str(e)}


# Global Sysmon integration instance
sysmon_integration = SysmonIntegration()


# API functions
async def start_sysmon_integration() -> str:
    """Start Sysmon integration"""
    try:
        await sysmon_integration.start()
        logger.info("Sysmon integration started")
        return "Sysmon integration started successfully"
    except Exception as e:
        logger.error(f"Error starting Sysmon integration: {e}")
        return f"Error starting Sysmon integration: {e}"


async def stop_sysmon_integration() -> str:
    """Stop Sysmon integration"""
    try:
        await sysmon_integration.stop()
        logger.info("Sysmon integration stopped")
        return "Sysmon integration stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping Sysmon integration: {e}")
        return f"Error stopping Sysmon integration: {e}"


def get_sysmon_events(limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get Sysmon events"""
    try:
        event_type_enum = SysmonEventType(int(event_type)) if event_type else None
        return sysmon_integration.get_events(limit, event_type_enum)
    except Exception as e:
        logger.error(f"Error getting Sysmon events: {e}")
        return []


def get_sysmon_statistics() -> Dict[str, Any]:
    """Get Sysmon integration statistics"""
    try:
        return sysmon_integration.get_statistics()
    except Exception as e:
        logger.error(f"Error getting Sysmon statistics: {e}")
        return {'error': str(e)}


def add_sysmon_callback(callback: Callable):
    """Add Sysmon event callback"""
    try:
        sysmon_integration.add_event_callback(callback)
        logger.info("Sysmon event callback added")
    except Exception as e:
        logger.error(f"Error adding Sysmon event callback: {e}")


def remove_sysmon_callback(callback: Callable):
    """Remove Sysmon event callback"""
    try:
        sysmon_integration.remove_event_callback(callback)
        logger.info("Sysmon event callback removed")
    except Exception as e:
        logger.error(f"Error removing Sysmon event callback: {e}"


# Initialize Sysmon integration
async def initialize_sysmon_integration() -> str:
    """Initialize Sysmon integration"""
    try:
        await start_sysmon_integration()
        logger.info("Sysmon integration initialized")
        return "Sysmon integration initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing Sysmon integration: {e}")
        return f"Error initializing Sysmon integration: {e}"


# Cleanup function
async def cleanup_sysmon_integration() -> str:
    """Cleanup Sysmon integration"""
    try:
        await stop_sysmon_integration()
        logger.info("Sysmon integration cleaned up")
        return "Sysmon integration cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up Sysmon integration: {e}")
        return f"Error cleaning up Sysmon integration: {e}"
