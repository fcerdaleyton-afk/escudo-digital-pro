#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Process Watcher
Advanced process monitoring and analysis for Windows systems
"""

import os
import sys
import asyncio
import logging
import json
import time
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque
from enum import Enum

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Windows-specific imports
try:
    import psutil
    import win32api
    import win32con
    import win32security
    import win32process
    import win32file
    import pywintypes
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
            logging.FileHandler(os.path.join(log_dir, 'process_analyzer.log')),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)


class ProcessThreatType(Enum):
    """Process threat type enumeration"""
    SUSPICIOUS_NAME = "suspicious_name"
    ENCODED_POWERSHELL = "encoded_powershell"
    UNSIGNED_BINARY = "unsigned_binary"
    ABNORMAL_SPAWNING = "abnormal_spawning"
    MEMORY_INJECTION = "memory_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LIVING_OFF_LAND = "living_off_land"
    SCHEDULED_TASK = "scheduled_task"


@dataclass
class ProcessThreat:
    """Process threat data structure"""
    threat_type: ProcessThreatType
    severity: float
    description: str
    evidence: Dict[str, Any]
    confidence: float


@dataclass
class ProcessSignature:
    """Process signature data structure"""
    is_signed: bool
    signer_name: Optional[str]
    timestamp: Optional[str]
    certificate_hash: Optional[str]
    verification_status: str


class ProcessAnalyzer:
    """Advanced process analyzer"""
    
    def __init__(self):
        """Initialize process analyzer"""
        self.suspicious_processes = set()
        self.whitelisted_processes = set()
        self.process_history: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        self.threat_patterns = self._initialize_threat_patterns()
        
        # Configuration
        self.config = {
            'max_history_per_process': 100,
            'spawn_threshold': 10,  # Max children before suspicious
            'analysis_interval': 5,  # seconds
            'enable_signature_check': True,
            'enable_behavior_analysis': True
        }
        
        # Initialize whitelisted processes
        self._initialize_whitelist()
        
        logger.info("Process analyzer initialized")
    
    def _initialize_threat_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize threat detection patterns"""
        return {
            'powershell_patterns': [
                {
                    'pattern': r'-enc\s+',
                    'description': 'Encoded PowerShell command',
                    'severity': 0.8,
                    'type': 'encoded_command'
                },
                {
                    'pattern': r'-encodedcommand\s+',
                    'description': 'Encoded PowerShell command',
                    'severity': 0.8,
                    'type': 'encoded_command'
                },
                {
                    'pattern': r'-e\s+',
                    'description': 'Short form encoded command',
                    'severity': 0.7,
                    'type': 'encoded_command'
                },
                {
                    'pattern': r'FromBase64String',
                    'description': 'Base64 decoding in PowerShell',
                    'severity': 0.7,
                    'type': 'base64_decode'
                },
                {
                    'pattern': r'IEX\s+',
                    'description': 'Invoke-Expression',
                    'severity': 0.6,
                    'type': 'invoke_expression'
                },
                {
                    'pattern': r'Invoke-Expression',
                    'description': 'Invoke-Expression full form',
                    'severity': 0.6,
                    'type': 'invoke_expression'
                },
                {
                    'pattern': r'Invoke-Evasion',
                    'description': 'PowerShell evasion techniques',
                    'severity': 0.9,
                    'type': 'evasion'
                },
                {
                    'pattern': r'-nop\s+',
                    'description': 'No profile execution',
                    'severity': 0.5,
                    'type': 'no_profile'
                },
                {
                    'pattern': r'-windowstyle\s+hidden',
                    'description': 'Hidden window execution',
                    'severity': 0.6,
                    'type': 'hidden_execution'
                },
                {
                    'pattern': r'-bypass\s+',
                    'description': 'Execution policy bypass',
                    'severity': 0.7,
                    'type': 'policy_bypass'
                }
            ],
            'suspicious_names': [
                {'name': 'powershell.exe', 'severity': 0.4, 'type': 'system_tool'},
                {'name': 'cmd.exe', 'severity': 0.3, 'type': 'system_tool'},
                {'name': 'wscript.exe', 'severity': 0.6, 'type': 'script_host'},
                {'name': 'cscript.exe', 'severity': 0.6, 'type': 'script_host'},
                {'name': 'rundll32.exe', 'severity': 0.7, 'type': 'dll_loader'},
                {'name': 'regsvr32.exe', 'severity': 0.7, 'type': 'dll_loader'},
                {'name': 'mshta.exe', 'severity': 0.8, 'type': 'html_application'},
                {'name': 'certutil.exe', 'severity': 0.6, 'type': 'certificate_utility'},
                {'name': 'bitsadmin.exe', 'severity': 0.7, 'type': 'background_transfer'},
                {'name': 'wmic.exe', 'severity': 0.5, 'type': 'management_interface'},
                {'name': 'tasklist.exe', 'severity': 0.3, 'type': 'system_utility'},
                {'name': 'net.exe', 'severity': 0.4, 'type': 'network_utility'},
                {'name': 'netsh.exe', 'severity': 0.5, 'type': 'network_shell'},
                {'name': 'findstr.exe', 'severity': 0.3, 'type': 'text_search'},
                {'name': 'whoami.exe', 'severity': 0.3, 'type': 'user_info'},
                {'name': 'systeminfo.exe', 'severity': 0.3, 'type': 'system_info'},
                {'name': 'ipconfig.exe', 'severity': 0.3, 'type': 'network_config'},
                {'name': 'ping.exe', 'severity': 0.2, 'type': 'network_test'},
                {'name': 'tracert.exe', 'severity': 0.2, 'type': 'network_trace'},
                {'name': 'nslookup.exe', 'severity': 0.2, 'type': 'dns_lookup'},
                {'name': 'ftp.exe', 'severity': 0.4, 'type': 'file_transfer'},
                {'name': 'tftp.exe', 'severity': 0.6, 'type': 'file_transfer'},
                {'name': 'telnet.exe', 'severity': 0.5, 'type': 'remote_access'},
                {'name': 'at.exe', 'severity': 0.6, 'type': 'task_scheduler'},
                {'name': 'schtasks.exe', 'severity': 0.5, 'type': 'task_scheduler'},
                {'name': 'sc.exe', 'severity': 0.5, 'type': 'service_control'},
                {'name': 'wevtutil.exe', 'severity': 0.4, 'type': 'event_utility'},
                {'name': 'wevtutil.exe', 'severity': 0.4, 'type': 'event_utility'},
                {'name': 'logman.exe', 'severity': 0.4, 'type': 'log_manager'},
                {'name': 'perfmon.exe', 'severity': 0.3, 'type': 'performance_monitor'},
                {'name': 'reg.exe', 'severity': 0.4, 'type': 'registry_editor'},
                {'name': 'regini.exe', 'severity': 0.5, 'type': 'registry_initializer'},
                {'name': 'regsvcs.exe', 'severity': 0.6, 'type': 'service_registration'},
                {'name': 'rasdial.exe', 'severity': 0.4, 'type': 'dial_up'},
                {'name': 'powershell_ise.exe', 'severity': 0.3, 'type': 'powershell_ide'},
                {'name': 'powershell_ise.exe', 'severity': 0.3, 'type': 'powershell_ide'}
            ],
            'living_off_land_tools': [
                'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
                'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
                'bitsadmin.exe', 'wmic.exe', 'net.exe', 'netsh.exe',
                'findstr.exe', 'whoami.exe', 'systeminfo.exe', 'ipconfig.exe',
                'ping.exe', 'tracert.exe', 'nslookup.exe', 'ftp.exe',
                'tftp.exe', 'telnet.exe', 'at.exe', 'schtasks.exe',
                'sc.exe', 'wevtutil.exe', 'logman.exe', 'reg.exe'
            ],
            'suspicious_arguments': [
                {
                    'pattern': r'/c\s+',
                    'description': 'Command execution',
                    'severity': 0.5
                },
                {
                    'pattern': r'/k\s+',
                    'description': 'Command execution with keep',
                    'severity': 0.5
                },
                {
                    'pattern': r'-exec\s+',
                    'description': 'Execution parameter',
                    'severity': 0.6
                },
                {
                    'pattern': r'-c\s+',
                    'description': 'Command execution',
                    'severity': 0.5
                },
                {
                    'pattern': r'-e\s+',
                    'description': 'Execution parameter',
                    'severity': 0.6
                },
                {
                    'pattern': r'--execute\s+',
                    'description': 'Execution parameter',
                    'severity': 0.6
                },
                {
                    'pattern': r'--eval\s+',
                    'description': 'Evaluation parameter',
                    'severity': 0.7
                }
            ]
        }
    
    def _initialize_whitelist(self):
        """Initialize process whitelist"""
        # Common system processes
        self.whitelisted_processes.update([
            'svchost.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe',
            'smss.exe', 'explorer.exe', 'dwm.exe', 'services.exe',
            'spoolsv.exe', 'alg.exe', 'wuauclt.exe', 'audiodg.exe',
            'conhost.exe', 'dllhost.exe', 'taskhost.exe', 'taskeng.exe',
            'rundll32.exe', 'wmiprvse.exe', 'wininit.exe', 'logonui.exe'
        ])
    
    async def analyze_process(self, pid: int, process_info: Dict[str, Any]) -> List[ProcessThreat]:
        """Analyze process for threats"""
        try:
            threats = []
            
            # Get detailed process information
            detailed_info = await self._get_detailed_process_info(pid)
            
            # Analyze process name
            name_threats = await self._analyze_process_name(detailed_info)
            threats.extend(name_threats)
            
            # Analyze command line
            cmd_threats = await self._analyze_command_line(detailed_info)
            threats.extend(cmd_threats)
            
            # Analyze digital signature
            if self.config['enable_signature_check']:
                signature_threats = await self._analyze_digital_signature(detailed_info)
                threats.extend(signature_threats)
            
            # Analyze behavior
            if self.config['enable_behavior_analysis']:
                behavior_threats = await self._analyze_process_behavior(detailed_info)
                threats.extend(behavior_threats)
            
            # Analyze parent-child relationships
            relationship_threats = await self._analyze_process_relationships(detailed_info)
            threats.extend(relationship_threats)
            
            # Store in history
            self._store_process_history(pid, detailed_info, threats)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error analyzing process {pid}: {e}")
            return []
    
    async def _get_detailed_process_info(self, pid: int) -> Dict[str, Any]:
        """Get detailed process information"""
        try:
            if not WINDOWS_AVAILABLE:
                return self._simulate_process_info(pid)
            
            process = psutil.Process(pid)
            
            # Basic info
            info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'cwd': process.cwd(),
                'ppid': process.ppid(),
                'username': process.username(),
                'create_time': datetime.fromtimestamp(process.create_time()),
                'status': process.status(),
                'nice': process.nice(),
                'memory_info': process.memory_info()._asdict(),
                'cpu_percent': process.cpu_percent(),
                'num_threads': process.num_threads(),
                'connections': [],
                'open_files': []
            }
            
            # Get network connections
            try:
                info['connections'] = [
                    {
                        'local_address': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_address': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status
                    }
                    for conn in process.connections()
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Get open files
            try:
                info['open_files'] = [
                    {'path': f.path, 'fd': f.fd}
                    for f in process.open_files()
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return self._simulate_process_info(pid)
        except Exception as e:
            logger.error(f"Error getting detailed process info: {e}")
            return self._simulate_process_info(pid)
    
    def _simulate_process_info(self, pid: int) -> Dict[str, Any]:
        """Simulate process info for non-Windows systems"""
        return {
            'pid': pid,
            'name': f'process_{pid}.exe',
            'exe': f'C:\\temp\\process_{pid}.exe',
            'cmdline': [f'process_{pid}.exe', '--suspicious'],
            'cwd': 'C:\\temp',
            'ppid': random.randint(1, 1000),
            'username': 'SYSTEM',
            'create_time': datetime.utcnow() - timedelta(minutes=random.randint(1, 60)),
            'status': 'running',
            'nice': 0,
            'memory_info': {'rss': random.randint(1000000, 10000000)},
            'cpu_percent': random.uniform(0.1, 10.0),
            'num_threads': random.randint(1, 10),
            'connections': [],
            'open_files': []
        }
    
    async def _analyze_process_name(self, process_info: Dict[str, Any]) -> List[ProcessThreat]:
        """Analyze process name for threats"""
        threats = []
        name = process_info.get('name', '').lower()
        
        # Check against suspicious names
        for suspicious in self.threat_patterns['suspicious_names']:
            if name == suspicious['name'].lower():
                threats.append(ProcessThreat(
                    threat_type=ProcessThreatType.SUSPICIOUS_NAME,
                    severity=suspicious['severity'],
                    description=f"Suspicious process name: {suspicious['name']}",
                    evidence={
                        'process_name': process_info['name'],
                        'type': suspicious['type']
                    },
                    confidence=0.8
                ))
        
        # Check for living-off-land binaries
        if name in self.threat_patterns['living_off_land_tools']:
            # Check if running from unusual location
            exe_path = process_info.get('exe', '').lower()
            system_paths = [
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\windows\\',
                'c:\\program files\\',
                'c:\\program files (x86)\\'
            ]
            
            is_system_location = any(exe_path.startswith(path) for path in system_paths)
            
            if not is_system_location:
                threats.append(ProcessThreat(
                    threat_type=ProcessThreatType.LIVING_OFF_LAND,
                    severity=0.8,
                    description=f"Living-off-land binary from unusual location: {name}",
                    evidence={
                        'process_name': process_info['name'],
                        'exe_path': process_info['exe'],
                        'expected_location': 'System32',
                        'actual_location': exe_path
                    },
                    confidence=0.9
                ))
        
        return threats
    
    async def _analyze_command_line(self, process_info: Dict[str, Any]) -> List[ProcessThreat]:
        """Analyze command line for threats"""
        threats = []
        cmdline = ' '.join(process_info.get('cmdline', []))
        
        # Check PowerShell patterns
        if 'powershell' in process_info.get('name', '').lower():
            for pattern_info in self.threat_patterns['powershell_patterns']:
                if re.search(pattern_info['pattern'], cmdline, re.IGNORECASE):
                    threats.append(ProcessThreat(
                        threat_type=ProcessThreatType.ENCODED_POWERSHELL,
                        severity=pattern_info['severity'],
                        description=f"PowerShell {pattern_info['description']}",
                        evidence={
                            'process_name': process_info['name'],
                            'command_line': cmdline,
                            'pattern': pattern_info['pattern'],
                            'type': pattern_info['type']
                        },
                        confidence=0.9
                    ))
        
        # Check for suspicious arguments
        for arg_pattern in self.threat_patterns['suspicious_arguments']:
            if re.search(arg_pattern['pattern'], cmdline, re.IGNORECASE):
                threats.append(ProcessThreat(
                    threat_type=ProcessThreatType.SUSPICIOUS_NAME,
                    severity=arg_pattern['severity'],
                    description=f"Suspicious command line argument: {arg_pattern['description']}",
                    evidence={
                        'process_name': process_info['name'],
                        'command_line': cmdline,
                        'pattern': arg_pattern['pattern']
                    },
                    confidence=0.7
                ))
        
        return threats
    
    async def _analyze_digital_signature(self, process_info: Dict[str, Any]) -> List[ProcessThreat]:
        """Analyze digital signature"""
        threats = []
        exe_path = process_info.get('exe')
        
        if not exe_path or not os.path.exists(exe_path):
            return threats
        
        try:
            signature = await self._verify_signature(exe_path)
            
            if not signature.is_signed:
                # Check if it should be signed
                suspicious_extensions = ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1']
                file_ext = os.path.splitext(exe_path)[1].lower()
                
                if file_ext in suspicious_extensions:
                    threats.append(ProcessThreat(
                        threat_type=ProcessThreatType.UNSIGNED_BINARY,
                        severity=0.7,
                        description=f"Unsigned binary: {process_info['name']}",
                        evidence={
                            'process_name': process_info['name'],
                            'exe_path': exe_path,
                            'file_extension': file_ext
                        },
                        confidence=0.8
                    ))
            
        except Exception as e:
            logger.error(f"Error analyzing digital signature: {e}")
        
        return threats
    
    async def _verify_signature(self, file_path: str) -> ProcessSignature:
        """Verify digital signature"""
        try:
            if not WINDOWS_AVAILABLE:
                return ProcessSignature(
                    is_signed=False,
                    signer_name=None,
                    timestamp=None,
                    certificate_hash=None,
                    verification_status="Windows modules not available"
                )
            
            # In real implementation, use Windows Authenticode APIs
            # For now, use simplified logic
            
            # Check if file is in system directories
            system_dirs = [
                'C:\\Windows\\System32',
                'C:\\Windows\\SysWOW64',
                'C:\\Program Files',
                'C:\\Program Files (x86)'
            ]
            
            is_system_file = any(file_path.startswith(dir) for dir in system_dirs)
            
            if is_system_file:
                return ProcessSignature(
                    is_signed=True,
                    signer_name="Microsoft Windows",
                    timestamp=datetime.utcnow().isoformat(),
                    certificate_hash="system_file_hash",
                    verification_status="Verified"
                )
            else:
                return ProcessSignature(
                    is_signed=False,
                    signer_name=None,
                    timestamp=None,
                    certificate_hash=None,
                    verification_status="Unsigned"
                )
                
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return ProcessSignature(
                is_signed=False,
                signer_name=None,
                timestamp=None,
                certificate_hash=None,
                verification_status=f"Error: {str(e)}"
            )
    
    async def _analyze_process_behavior(self, process_info: Dict[str, Any]) -> List[ProcessThreat]:
        """Analyze process behavior"""
        threats = []
        pid = process_info.get('pid')
        
        # Check for abnormal spawning
        child_count = await self._get_child_process_count(pid)
        if child_count > self.config['spawn_threshold']:
            threats.append(ProcessThreat(
                threat_type=ProcessThreatType.ABNORMAL_SPAWNING,
                severity=0.8,
                description=f"Process spawning too many children: {child_count}",
                evidence={
                    'process_name': process_info['name'],
                    'child_count': child_count,
                    'threshold': self.config['spawn_threshold']
                },
                confidence=0.9
            ))
        
        # Check for network connections
        connections = process_info.get('connections', [])
        suspicious_connections = [
            conn for conn in connections
            if conn.get('remote_address') and conn.get('remote_port') in [4444, 5555, 6667, 8080, 9999, 31337]
        ]
        
        if suspicious_connections:
            threats.append(ProcessThreat(
                threat_type=ProcessThreatType.SUSPICIOUS_NAME,
                severity=0.6,
                description=f"Process has suspicious network connections",
                evidence={
                    'process_name': process_info['name'],
                    'suspicious_connections': suspicious_connections
                },
                confidence=0.7
            ))
        
        return threats
    
    async def _get_child_process_count(self, parent_pid: int) -> int:
        """Get child process count"""
        try:
            if not WINDOWS_AVAILABLE:
                return random.randint(0, 20)
            
            count = 0
            for proc in psutil.process_iter(['pid', 'ppid']):
                try:
                    if proc.info['ppid'] == parent_pid:
                        count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return count
            
        except Exception as e:
            logger.error(f"Error getting child process count: {e}")
            return 0
    
    async def _analyze_process_relationships(self, process_info: Dict[str, Any]) -> List[ProcessThreat]:
        """Analyze parent-child relationships"""
        threats = []
        pid = process_info.get('pid')
        ppid = process_info.get('ppid')
        
        # Check if parent is suspicious
        if ppid and ppid in self.suspicious_processes:
            threats.append(ProcessThreat(
                threat_type=ProcessThreatType.SUSPICIOUS_NAME,
                severity=0.6,
                description=f"Process spawned by suspicious parent",
                evidence={
                    'process_name': process_info['name'],
                    'parent_pid': ppid,
                    'parent_suspicious': True
                },
                confidence=0.7
            ))
        
        # Check for unusual parent-child combinations
        child_name = process_info.get('name', '').lower()
        if ppid:
            try:
                if WINDOWS_AVAILABLE:
                    parent = psutil.Process(ppid)
                    parent_name = parent.name().lower()
                else:
                    parent_name = f'parent_{ppid}.exe'
                
                # Suspicious parent-child combinations
                suspicious_combinations = [
                    ('powershell.exe', 'cmd.exe'),
                    ('cmd.exe', 'powershell.exe'),
                    ('rundll32.exe', 'powershell.exe'),
                    ('wscript.exe', 'powershell.exe'),
                    ('mshta.exe', 'powershell.exe'),
                    ('certutil.exe', 'cmd.exe')
                ]
                
                for (parent_prog, child_prog) in suspicious_combinations:
                    if parent_name == parent_prog and child_name == child_prog:
                        threats.append(ProcessThreat(
                            threat_type=ProcessThreatType.SUSPICIOUS_NAME,
                            severity=0.7,
                            description=f"Suspicious parent-child relationship: {parent_name} -> {child_name}",
                            evidence={
                                'parent_name': parent_name,
                                'child_name': child_name,
                                'parent_pid': ppid,
                                'child_pid': pid
                            },
                            confidence=0.8
                        ))
                        break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return threats
    
    def _store_process_history(self, pid: int, process_info: Dict[str, Any], threats: List[ProcessThreat]):
        """Store process analysis in history"""
        try:
            history_entry = {
                'timestamp': datetime.utcnow(),
                'process_info': process_info,
                'threats': [threat.__dict__ for threat in threats],
                'threat_count': len(threats),
                'max_threat_severity': max([t.severity for t in threats]) if threats else 0.0
            }
            
            self.process_history[pid].append(history_entry)
            
            # Limit history size
            if len(self.process_history[pid]) > self.config['max_history_per_process']:
                self.process_history[pid].pop(0)
                
        except Exception as e:
            logger.error(f"Error storing process history: {e}")
    
    def get_process_history(self, pid: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get process analysis history"""
        try:
            history = self.process_history.get(pid, [])
            return history[-limit:] if history else []
        except Exception as e:
            logger.error(f"Error getting process history: {e}")
            return []
    
    def get_all_threats(self, min_severity: float = 0.5) -> List[Dict[str, Any]]:
        """Get all recent threats above severity threshold"""
        try:
            all_threats = []
            
            for pid, history in self.process_history.items():
                for entry in history:
                    if entry['max_threat_severity'] >= min_severity:
                        all_threats.append({
                            'pid': pid,
                            'timestamp': entry['timestamp'],
                            'process_name': entry['process_info'].get('name'),
                            'threats': entry['threats'],
                            'max_threat_severity': entry['max_threat_severity']
                        })
            
            # Sort by timestamp and severity
            all_threats.sort(key=lambda x: (x['timestamp'], x['max_threat_severity']), reverse=True)
            
            return all_threats
            
        except Exception as e:
            logger.error(f"Error getting all threats: {e}")
            return []
    
    def add_to_whitelist(self, process_name: str):
        """Add process to whitelist"""
        self.whitelisted_processes.add(process_name.lower())
        logger.info(f"Added {process_name} to whitelist")
    
    def remove_from_whitelist(self, process_name: str):
        """Remove process from whitelist"""
        self.whitelisted_processes.discard(process_name.lower())
        logger.info(f"Removed {process_name} from whitelist")
    
    def is_whitelisted(self, process_name: str) -> bool:
        """Check if process is whitelisted"""
        return process_name.lower() in self.whitelisted_processes
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        try:
            total_processes = len(self.process_history)
            total_threats = sum(len(entry['threats']) for history in self.process_history.values() for entry in history)
            
            threat_counts = defaultdict(int)
            for history in self.process_history.values():
                for entry in history:
                    for threat in entry['threats']:
                        threat_counts[threat['threat_type']] += 1
            
            return {
                'total_processes_analyzed': total_processes,
                'total_threats_detected': total_threats,
                'whitelisted_processes': len(self.whitelisted_processes),
                'suspicious_processes': len(self.suspicious_processes),
                'threat_type_distribution': dict(threat_counts),
                'config': self.config
            }
            
        except Exception as e:
            logger.error(f"Error getting analyzer statistics: {e}")
            return {'error': str(e)}


# Global process analyzer instance
process_analyzer = ProcessAnalyzer()


# API functions
async def analyze_process(pid: int, process_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze process for threats"""
    try:
        threats = await process_analyzer.analyze_process(pid, process_info)
        return [threat.__dict__ for threat in threats]
    except Exception as e:
        logger.error(f"Error analyzing process: {e}")
        return []


def get_process_history(pid: int, limit: int = 50) -> List[Dict[str, Any]]:
    """Get process analysis history"""
    try:
        return process_analyzer.get_process_history(pid, limit)
    except Exception as e:
        logger.error(f"Error getting process history: {e}")
        return []


def get_all_threats(min_severity: float = 0.5) -> List[Dict[str, Any]]:
    """Get all recent threats"""
    try:
        return process_analyzer.get_all_threats(min_severity)
    except Exception as e:
        logger.error(f"Error getting all threats: {e}")
        return []


def get_analyzer_statistics() -> Dict[str, Any]:
    """Get analyzer statistics"""
    try:
        return process_analyzer.get_statistics()
    except Exception as e:
        logger.error(f"Error getting analyzer statistics: {e}")
        return {'error': str(e)}


def add_process_to_whitelist(process_name: str) -> str:
    """Add process to whitelist"""
    try:
        process_analyzer.add_to_whitelist(process_name)
        return f"Added {process_name} to whitelist"
    except Exception as e:
        logger.error(f"Error adding to whitelist: {e}")
        return f"Error adding to whitelist: {e}"


def remove_process_from_whitelist(process_name: str) -> str:
    """Remove process from whitelist"""
    try:
        process_analyzer.remove_from_whitelist(process_name)
        return f"Removed {process_name} from whitelist"
    except Exception as e:
        logger.error(f"Error removing from whitelist: {e}")
        return f"Error removing from whitelist: {e}"
