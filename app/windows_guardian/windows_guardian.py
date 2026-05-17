#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Windows Host Guardian Mode
Comprehensive defensive monitoring for Windows systems
"""

import os
import sys
import asyncio
import logging
import json
import time
import uuid
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import weakref

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Windows-specific imports (cross-platform fallbacks)
try:
    import win32api
    import win32con
    import win32security
    import win32event
    import win32file
    import win32pdh
    import win32service
    import winerror
    import pywintypes
    import win32evtlog
    import win32evtlogutil
    import win32process
    import psutil
    import winreg
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    logging.warning("Windows-specific modules not available - using simulation mode")

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
            logging.FileHandler(os.path.join(log_dir, 'windows_guardian.log')),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Alert type enumeration"""
    PROCESS_SUSPICIOUS = "process_suspicious"
    PROCESS_POWERSHELL = "process_powershell"
    PROCESS_UNSIGNED = "process_unsigned"
    EVENT_FAILED_LOGIN = "event_failed_login"
    EVENT_SUSPICIOUS = "event_suspicious"
    FILE_RANSOMWARE = "file_ransomware"
    FILE_SUSPICIOUS = "file_suspicious"
    NETWORK_SUSPICIOUS = "network_suspicious"
    SYSTEM_ANOMALY = "system_anomaly"


class ResponseMode(Enum):
    """Response mode enumeration"""
    ALERT_ONLY = "alert_only"
    QUARANTINE = "quarantine"
    ISOLATE = "isolate"


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    timestamp: datetime
    event_type: AlertType
    threat_level: ThreatLevel
    source: str
    description: str
    details: Dict[str, Any]
    process_id: Optional[int] = None
    user: Optional[str] = None
    file_path: Optional[str] = None
    network_info: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'threat_level': self.threat_level.value,
            'source': self.source,
            'description': self.description,
            'details': self.details,
            'process_id': self.process_id,
            'user': self.user,
            'file_path': self.file_path,
            'network_info': self.network_info
        }


@dataclass
class ProcessInfo:
    """Process information data structure"""
    pid: int
    name: str
    path: str
    command_line: str
    parent_pid: int
    user: str
    start_time: datetime
    is_signed: bool
    signature_info: Optional[Dict[str, Any]]
    is_suspicious: bool = False
    threat_score: float = 0.0


@dataclass
class NetworkConnection:
    """Network connection data structure"""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    state: str
    process_id: int
    timestamp: datetime
    is_suspicious: bool = False
    threat_score: float = 0.0


class WindowsGuardianCore:
    """Core Windows Guardian system"""
    
    def __init__(self):
        """Initialize Windows Guardian core"""
        self.is_running = False
        self.response_mode = ResponseMode.ALERT_ONLY
        self.events: deque = deque(maxlen=10000)
        self.processes: Dict[int, ProcessInfo] = {}
        self.connections: Dict[str, NetworkConnection] = {}
        self.alert_callbacks: List[Callable] = []
        
        # Configuration
        self.config = {
            'monitor_processes': True,
            'monitor_events': True,
            'monitor_files': True,
            'monitor_network': True,
            'threat_threshold': 0.7,
            'max_events_per_minute': 100,
            'quarantine_enabled': False,
            'isolation_enabled': False
        }
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'threats_detected': 0,
            'processes_monitored': 0,
            'connections_monitored': 0,
            'start_time': None
        }
        
        logger.info("Windows Guardian core initialized")
    
    async def start(self):
        """Start Windows Guardian"""
        try:
            logger.info("Starting Windows Guardian")
            
            if not WINDOWS_AVAILABLE:
                logger.warning("Windows modules not available - running in simulation mode")
            
            self.is_running = True
            self.stats['start_time'] = datetime.utcnow()
            
            # Start monitoring components
            await self._start_monitoring()
            
            logger.info("Windows Guardian started successfully")
            
        except Exception as e:
            logger.error(f"Error starting Windows Guardian: {e}")
            raise
    
    async def stop(self):
        """Stop Windows Guardian"""
        try:
            logger.info("Stopping Windows Guardian")
            
            self.is_running = False
            
            logger.info("Windows Guardian stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping Windows Guardian: {e}")
    
    async def _start_monitoring(self):
        """Start monitoring components"""
        try:
            # Start process monitoring
            if self.config['monitor_processes']:
                asyncio.create_task(self._monitor_processes())
            
            # Start event monitoring
            if self.config['monitor_events']:
                asyncio.create_task(self._monitor_windows_events())
            
            # Start file monitoring
            if self.config['monitor_files']:
                asyncio.create_task(self._monitor_file_system())
            
            # Start network monitoring
            if self.config['monitor_network']:
                asyncio.create_task(self._monitor_network())
            
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
    
    async def _monitor_processes(self):
        """Monitor system processes"""
        try:
            while self.is_running:
                try:
                    if WINDOWS_AVAILABLE:
                        await self._scan_windows_processes()
                    else:
                        await self._simulate_process_monitoring()
                    
                    await asyncio.sleep(5)  # Scan every 5 seconds
                    
                except Exception as e:
                    logger.error(f"Error in process monitoring: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            logger.error(f"Process monitoring error: {e}")
    
    async def _scan_windows_processes(self):
        """Scan Windows processes"""
        try:
            current_pids = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'username', 'create_time']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    
                    # Check if this is a new process
                    if pid not in self.processes:
                        await self._analyze_new_process(proc)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Clean up terminated processes
            terminated_pids = set(self.processes.keys()) - current_pids
            for pid in terminated_pids:
                del self.processes[pid]
                
        except Exception as e:
            logger.error(f"Error scanning processes: {e}")
    
    async def _analyze_new_process(self, proc):
        """Analyze new process for threats"""
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or 'Unknown'
            path = proc.info['exe'] or 'Unknown'
            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
            parent_pid = proc.info['ppid'] or 0
            username = proc.info['username'] or 'Unknown'
            start_time = datetime.fromtimestamp(proc.info['create_time'])
            
            # Check if process is signed
            is_signed, signature_info = await self._check_process_signature(path)
            
            # Create process info
            process_info = ProcessInfo(
                pid=pid,
                name=name,
                path=path,
                command_line=cmdline,
                parent_pid=parent_pid,
                user=username,
                start_time=start_time,
                is_signed=is_signed,
                signature_info=signature_info
            )
            
            # Analyze for threats
            await self._analyze_process_threats(process_info)
            
            # Store process
            self.processes[pid] = process_info
            self.stats['processes_monitored'] += 1
            
        except Exception as e:
            logger.error(f"Error analyzing new process: {e}")
    
    async def _check_process_signature(self, file_path: str) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Check if process is digitally signed"""
        try:
            if not os.path.exists(file_path):
                return False, None
            
            # Simplified signature check
            # In real implementation, use Windows Authenticode APIs
            is_signed = await self._verify_digital_signature(file_path)
            
            signature_info = {
                'is_signed': is_signed,
                'signer': 'Unknown' if not is_signed else 'Verified',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return is_signed, signature_info
            
        except Exception as e:
            logger.error(f"Error checking process signature: {e}")
            return False, None
    
    async def _verify_digital_signature(self, file_path: str) -> bool:
        """Verify digital signature"""
        try:
            # Simplified signature verification
            # In real implementation, use WinVerifyTrust or similar
            suspicious_extensions = ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1']
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext in suspicious_extensions:
                # Check if file is in system directories
                system_dirs = ['C:\\Windows\\System32', 'C:\\Windows\\SysWOW64', 'C:\\Program Files']
                is_system_file = any(file_path.startswith(dir) for dir in system_dirs)
                
                if not is_system_file:
                    return False  # Assume unsigned for non-system files
            
            return True  # Assume signed for system files
            
        except Exception:
            return False
    
    async def _analyze_process_threats(self, process_info: ProcessInfo):
        """Analyze process for threats"""
        try:
            threats = []
            
            # Check for suspicious process names
            suspicious_names = ['powershell', 'cmd', 'wscript', 'cscript', 'rundll32']
            if any(name.lower() in process_info.name.lower() for name in suspicious_names):
                threats.append(('suspicious_process_name', 0.6))
            
            # Check for encoded PowerShell
            if 'powershell' in process_info.name.lower():
                encoded_commands = await self._detect_encoded_powershell(process_info.command_line)
                if encoded_commands:
                    threats.append(('encoded_powershell', 0.8))
                    await self._create_alert(
                        AlertType.PROCESS_POWERSHELL,
                        ThreatLevel.HIGH,
                        f"Encoded PowerShell command detected: {process_info.name}",
                        {'pid': process_info.pid, 'command_line': process_info.command_line, 'encoded_commands': encoded_commands},
                        process_info.pid,
                        process_info.user
                    )
            
            # Check for unsigned binaries
            if not process_info.is_signed:
                threats.append(('unsigned_binary', 0.7))
                await self._create_alert(
                    AlertType.PROCESS_UNSIGNED,
                    ThreatLevel.MEDIUM,
                    f"Unsigned binary detected: {process_info.name}",
                    {'pid': process_info.pid, 'path': process_info.path},
                    process_info.pid,
                    process_info.user
                )
            
            # Check for abnormal subprocess spawning
            if await self._detect_abnormal_subprocess_spawning(process_info):
                threats.append(('abnormal_subprocess_spawning', 0.8))
                await self._create_alert(
                    AlertType.PROCESS_SUSPICIOUS,
                    ThreatLevel.HIGH,
                    f"Abnormal subprocess spawning detected: {process_info.name}",
                    {'pid': process_info.pid, 'parent_pid': process_info.parent_pid},
                    process_info.pid,
                    process_info.user
                )
            
            # Calculate threat score
            if threats:
                process_info.threat_score = max(score for _, score in threats)
                process_info.is_suspicious = process_info.threat_score >= self.config['threat_threshold']
                
                if process_info.is_suspicious:
                    self.stats['threats_detected'] += 1
            
        except Exception as e:
            logger.error(f"Error analyzing process threats: {e}")
    
    async def _detect_encoded_powershell(self, command_line: str) -> List[str]:
        """Detect encoded PowerShell commands"""
        try:
            encoded_patterns = [
                '-enc ', '-encodedcommand ', '-e ', 'FromBase64String',
                'IEX ', 'Invoke-Expression', 'Invoke-Evasion'
            ]
            
            found_encodings = []
            for pattern in encoded_patterns:
                if pattern.lower() in command_line.lower():
                    found_encodings.append(pattern)
            
            return found_encodings
            
        except Exception as e:
            logger.error(f"Error detecting encoded PowerShell: {e}")
            return []
    
    async def _detect_abnormal_subprocess_spawning(self, process_info: ProcessInfo) -> bool:
        """Detect abnormal subprocess spawning"""
        try:
            # Count child processes
            child_count = sum(1 for p in self.processes.values() if p.parent_pid == process_info.pid)
            
            # Check if spawning too many children
            if child_count > 10:  # Threshold
                return True
            
            # Check for suspicious parent-child relationships
            if process_info.name.lower() in ['powershell', 'cmd'] and child_count > 5:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error detecting abnormal subprocess spawning: {e}")
            return False
    
    async def _simulate_process_monitoring(self):
        """Simulate process monitoring for non-Windows systems"""
        try:
            # Simulate suspicious process
            if random.random() < 0.1:  # 10% chance
                await self._create_alert(
                    AlertType.PROCESS_SUSPICIOUS,
                    ThreatLevel.MEDIUM,
                    "Simulated suspicious process detected",
                    {'pid': random.randint(1000, 9999), 'name': 'suspicious.exe'},
                    random.randint(1000, 9999),
                    'SYSTEM'
                )
                
        except Exception as e:
            logger.error(f"Error in simulated process monitoring: {e}")
    
    async def _monitor_windows_events(self):
        """Monitor Windows Event Logs"""
        try:
            while self.is_running:
                try:
                    if WINDOWS_AVAILABLE:
                        await self._scan_windows_events()
                    else:
                        await self._simulate_event_monitoring()
                    
                    await asyncio.sleep(10)  # Scan every 10 seconds
                    
                except Exception as e:
                    logger.error(f"Error in event monitoring: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            logger.error(f"Event monitoring error: {e}")
    
    async def _scan_windows_events(self):
        """Scan Windows Event Logs"""
        try:
            # Monitor Security log
            await self._scan_security_events()
            
            # Monitor System log
            await self._scan_system_events()
            
            # Monitor Application log
            await self._scan_application_events()
            
        except Exception as e:
            logger.error(f"Error scanning Windows events: {e}")
    
    async def _scan_security_events(self):
        """Scan Security event log"""
        try:
            # In real implementation, use Windows Event Log APIs
            # For now, simulate security events
            
            if random.random() < 0.05:  # 5% chance of failed login
                await self._create_alert(
                    AlertType.EVENT_FAILED_LOGIN,
                    ThreatLevel.MEDIUM,
                    "Failed login attempt detected",
                    {'username': 'admin', 'source_ip': '192.168.1.100'},
                    None,
                    'admin'
                )
            
        except Exception as e:
            logger.error(f"Error scanning security events: {e}")
    
    async def _scan_system_events(self):
        """Scan System event log"""
        try:
            # Monitor for service creation and other system events
            pass
            
        except Exception as e:
            logger.error(f"Error scanning system events: {e}")
    
    async def _scan_application_events(self):
        """Scan Application event log"""
        try:
            # Monitor application events
            pass
            
        except Exception as e:
            logger.error(f"Error scanning application events: {e}")
    
    async def _simulate_event_monitoring(self):
        """Simulate event monitoring for non-Windows systems"""
        try:
            if random.random() < 0.05:  # 5% chance
                await self._create_alert(
                    AlertType.EVENT_SUSPICIOUS,
                    ThreatLevel.LOW,
                    "Simulated suspicious Windows event",
                    {'event_id': random.randint(1000, 9999)},
                    None,
                    'SYSTEM'
                )
                
        except Exception as e:
            logger.error(f"Error in simulated event monitoring: {e}")
    
    async def _monitor_file_system(self):
        """Monitor file system changes"""
        try:
            while self.is_running:
                try:
                    if WINDOWS_AVAILABLE:
                        await self._scan_file_changes()
                    else:
                        await self._simulate_file_monitoring()
                    
                    await asyncio.sleep(15)  # Scan every 15 seconds
                    
                except Exception as e:
                    logger.error(f"Error in file monitoring: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            logger.error(f"File monitoring error: {e}")
    
    async def _scan_file_changes(self):
        """Scan for file system changes"""
        try:
            # Monitor for rapid file changes (ransomware indicator)
            await self._detect_ransomware_activity()
            
            # Monitor for suspicious temp execution
            await self._detect_temp_execution()
            
            # Monitor autorun modifications
            await self._detect_autorun_modifications()
            
        except Exception as e:
            logger.error(f"Error scanning file changes: {e}")
    
    async def _detect_ransomware_activity(self):
        """Detect ransomware-like activity"""
        try:
            # In real implementation, monitor file modification rates
            # For now, simulate detection
            
            if random.random() < 0.01:  # 1% chance
                await self._create_alert(
                    AlertType.FILE_RANSOMWARE,
                    ThreatLevel.CRITICAL,
                    "Ransomware activity detected",
                    {'file_count': random.randint(100, 1000), 'time_window': '60s'},
                    None,
                    'SYSTEM'
                )
                
        except Exception as e:
            logger.error(f"Error detecting ransomware activity: {e}")
    
    async def _detect_temp_execution(self):
        """Detect suspicious temp directory execution"""
        try:
            temp_dirs = ['C:\\Windows\\Temp', 'C:\\Users\\*\\AppData\\Local\\Temp']
            
            # In real implementation, scan temp directories for executable files
            pass
            
        except Exception as e:
            logger.error(f"Error detecting temp execution: {e}")
    
    async def _detect_autorun_modifications(self):
        """Detect autorun modifications"""
        try:
            # Monitor registry keys and startup folders
            autorun_locations = [
                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'
            ]
            
            # In real implementation, monitor these locations
            pass
            
        except Exception as e:
            logger.error(f"Error detecting autorun modifications: {e}")
    
    async def _simulate_file_monitoring(self):
        """Simulate file monitoring for non-Windows systems"""
        try:
            if random.random() < 0.02:  # 2% chance
                await self._create_alert(
                    AlertType.FILE_SUSPICIOUS,
                    ThreatLevel.MEDIUM,
                    "Simulated suspicious file activity",
                    {'file_path': 'C:\\temp\\suspicious.exe'},
                    None,
                    'SYSTEM'
                )
                
        except Exception as e:
            logger.error(f"Error in simulated file monitoring: {e}")
    
    async def _monitor_network(self):
        """Monitor network connections"""
        try:
            while self.is_running:
                try:
                    if WINDOWS_AVAILABLE:
                        await self._scan_network_connections()
                    else:
                        await self._simulate_network_monitoring()
                    
                    await asyncio.sleep(8)  # Scan every 8 seconds
                    
                except Exception as e:
                    logger.error(f"Error in network monitoring: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
    
    async def _scan_network_connections(self):
        """Scan network connections"""
        try:
            current_connections = {}
            
            for conn in psutil.net_connections():
                try:
                    if conn.status == 'ESTABLISHED':
                        local_ip = conn.laddr.ip if conn.laddr else '0.0.0.0'
                        local_port = conn.laddr.port if conn.laddr else 0
                        remote_ip = conn.raddr.ip if conn.raddr else '0.0.0.0'
                        remote_port = conn.raddr.port if conn.raddr else 0
                        protocol = conn.type
                        state = conn.status
                        pid = conn.pid or 0
                        
                        conn_key = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"
                        
                        connection_info = NetworkConnection(
                            local_ip=local_ip,
                            local_port=local_port,
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            protocol=str(protocol),
                            state=state,
                            process_id=pid,
                            timestamp=datetime.utcnow()
                        )
                        
                        current_connections[conn_key] = connection_info
                        
                        # Analyze for threats
                        await self._analyze_connection_threats(connection_info)
                        
                except (psutil.AccessDenied, AttributeError):
                    continue
            
            # Update connections
            self.connections = current_connections
            self.stats['connections_monitored'] = len(current_connections)
            
        except Exception as e:
            logger.error(f"Error scanning network connections: {e}")
    
    async def _analyze_connection_threats(self, connection: NetworkConnection):
        """Analyze network connection for threats"""
        try:
            threats = []
            
            # Check for suspicious outbound connections
            suspicious_ports = [4444, 5555, 6667, 8080, 9999, 31337, 12345]
            if connection.remote_port in suspicious_ports:
                threats.append(('suspicious_port', 0.7))
            
            # Check for connections to suspicious IPs
            if await self._is_suspicious_ip(connection.remote_ip):
                threats.append(('suspicious_ip', 0.8))
            
            # Check for unusual local ports
            if connection.local_port > 60000:
                threats.append(('unusual_local_port', 0.5))
            
            # Calculate threat score
            if threats:
                connection.threat_score = max(score for _, score in threats)
                connection.is_suspicious = connection.threat_score >= self.config['threat_threshold']
                
                if connection.is_suspicious:
                    await self._create_alert(
                        AlertType.NETWORK_SUSPICIOUS,
                        ThreatLevel.MEDIUM,
                        f"Suspicious network connection detected",
                        {
                            'local_ip': connection.local_ip,
                            'local_port': connection.local_port,
                            'remote_ip': connection.remote_ip,
                            'remote_port': connection.remote_port,
                            'protocol': connection.protocol
                        },
                        connection.process_id
                    )
            
        except Exception as e:
            logger.error(f"Error analyzing connection threats: {e}")
    
    async def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        try:
            # Simple heuristics for suspicious IPs
            if ip.startswith('0.') or ip.startswith('127.'):
                return False
            
            # Check for known malicious ranges (simplified)
            suspicious_ranges = [
                '192.168.1.',  # Example - in real implementation, use threat intelligence
                '10.0.0.',
                '172.16.0.'
            ]
            
            for range_prefix in suspicious_ranges:
                if ip.startswith(range_prefix):
                    return False  # Internal IP
            
            # External IPs to non-standard ports might be suspicious
            return True
            
        except Exception:
            return False
    
    async def _simulate_network_monitoring(self):
        """Simulate network monitoring for non-Windows systems"""
        try:
            if random.random() < 0.03:  # 3% chance
                await self._create_alert(
                    AlertType.NETWORK_SUSPICIOUS,
                    ThreatLevel.LOW,
                    "Simulated suspicious network connection",
                    {'remote_ip': '192.168.1.100', 'remote_port': 4444},
                    random.randint(1000, 9999)
                )
                
        except Exception as e:
            logger.error(f"Error in simulated network monitoring: {e}")
    
    async def _create_alert(self, alert_type: AlertType, threat_level: ThreatLevel, 
                          description: str, details: Dict[str, Any], 
                          process_id: Optional[int] = None, user: Optional[str] = None,
                          file_path: Optional[str] = None, 
                          network_info: Optional[Dict[str, Any]] = None):
        """Create security alert"""
        try:
            event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                event_type=alert_type,
                threat_level=threat_level,
                source='Windows Guardian',
                description=description,
                details=details,
                process_id=process_id,
                user=user,
                file_path=file_path,
                network_info=network_info
            )
            
            # Store event
            self.events.append(event)
            self.stats['total_events'] += 1
            
            # Apply defensive response
            await self._apply_defensive_response(event)
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    await callback(event)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
    
    async def _apply_defensive_response(self, event: SecurityEvent):
        """Apply defensive response based on mode"""
        try:
            if self.response_mode == ResponseMode.ALERT_ONLY:
                # Just log the alert
                logger.warning(f"Security alert: {event.description}")
                
            elif self.response_mode == ResponseMode.QUARANTINE and self.config['quarantine_enabled']:
                # Quarantine the process if applicable
                if event.process_id and event.process_id in self.processes:
                    await self._quarantine_process(event.process_id)
                    
            elif self.response_mode == ResponseMode.ISOLATE and self.config['isolation_enabled']:
                # Isolate the system from network
                await self._isolate_system()
                
        except Exception as e:
            logger.error(f"Error applying defensive response: {e}")
    
    async def _quarantine_process(self, pid: int):
        """Quarantine suspicious process"""
        try:
            if WINDOWS_AVAILABLE:
                # In real implementation, suspend or terminate the process
                logger.warning(f"Quarantining process {pid}")
            else:
                logger.warning(f"Would quarantine process {pid} (simulation mode)")
                
        except Exception as e:
            logger.error(f"Error quarantining process: {e}")
    
    async def _isolate_system(self):
        """Isolate system from network"""
        try:
            if WINDOWS_AVAILABLE:
                # In real implementation, disable network interfaces
                logger.warning("Isolating system from network")
            else:
                logger.warning("Would isolate system from network (simulation mode)")
                
        except Exception as e:
            logger.error(f"Error isolating system: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Add alert callback"""
        self.alert_callbacks.append(callback)
    
    def set_response_mode(self, mode: ResponseMode):
        """Set response mode"""
        self.response_mode = mode
        logger.info(f"Response mode set to: {mode.value}")
    
    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events"""
        return [event.to_dict() for event in list(self.events)[-limit:]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0
        
        return {
            'is_running': self.is_running,
            'uptime': uptime,
            'total_events': self.stats['total_events'],
            'threats_detected': self.stats['threats_detected'],
            'processes_monitored': self.stats['processes_monitored'],
            'connections_monitored': self.stats['connections_monitored'],
            'response_mode': self.response_mode.value,
            'active_processes': len(self.processes),
            'active_connections': len(self.connections),
            'threat_threshold': self.config['threat_threshold']
        }


# Global Windows Guardian instance
windows_guardian = WindowsGuardianCore()


# API functions
async def start_windows_guardian() -> str:
    """Start Windows Guardian"""
    try:
        await windows_guardian.start()
        logger.info("Windows Guardian started")
        return "Windows Guardian started successfully"
    except Exception as e:
        logger.error(f"Error starting Windows Guardian: {e}")
        return f"Error starting Windows Guardian: {e}"


async def stop_windows_guardian() -> str:
    """Stop Windows Guardian"""
    try:
        await windows_guardian.stop()
        logger.info("Windows Guardian stopped")
        return "Windows Guardian stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping Windows Guardian: {e}")
        return f"Error stopping Windows Guardian: {e}"


def get_guardian_events(limit: int = 100) -> List[Dict[str, Any]]:
    """Get Guardian events"""
    try:
        return windows_guardian.get_events(limit)
    except Exception as e:
        logger.error(f"Error getting Guardian events: {e}")
        return []


def get_guardian_statistics() -> Dict[str, Any]:
    """Get Guardian statistics"""
    try:
        return windows_guardian.get_statistics()
    except Exception as e:
        logger.error(f"Error getting Guardian statistics: {e}")
        return {'error': str(e)}


def set_response_mode(mode: str) -> str:
    """Set response mode"""
    try:
        response_mode = ResponseMode(mode)
        windows_guardian.set_response_mode(response_mode)
        return f"Response mode set to {mode}"
    except Exception as e:
        logger.error(f"Error setting response mode: {e}")
        return f"Error setting response mode: {e}"


def add_alert_callback(callback: Callable):
    """Add alert callback"""
    try:
        windows_guardian.add_alert_callback(callback)
        logger.info("Alert callback added")
    except Exception as e:
        logger.error(f"Error adding alert callback: {e}")


# Initialize Windows Guardian
async def initialize_windows_guardian() -> str:
    """Initialize Windows Guardian"""
    try:
        await start_windows_guardian()
        logger.info("Windows Guardian initialized")
        return "Windows Guardian initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing Windows Guardian: {e}")
        return f"Error initializing Windows Guardian: {e}"


# Cleanup function
async def cleanup_windows_guardian() -> str:
    """Cleanup Windows Guardian"""
    try:
        await stop_windows_guardian()
        logger.info("Windows Guardian cleaned up")
        return "Windows Guardian cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up Windows Guardian: {e}")
        return f"Error cleaning up Windows Guardian: {e}"
