"""
MARY V5 SHIELD CORE - Defensive Windows Analyzer
Windows-specific suspicious activity detection (DEFENSIVE ONLY)
"""

import os
import time
import json
import asyncio
import subprocess
import threading
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
import psutil
import re

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class WindowsThreatType(Enum):
    """Windows-specific threat types (DEFENSIVE ONLY)"""
    SUSPICIOUS_SCHEDULED_TASK = "suspicious_scheduled_task"
    REGISTRY_AUTORUN = "registry_autorun"
    STARTUP_PERSISTENCE = "startup_persistence"
    UNSIGNED_BINARY = "unsigned_binary"
    ENCODED_POWERSHELL = "encoded_powershell"
    SUSPICIOUS_WMI = "suspicious_wmi"
    SUSPICIOUS_SERVICE = "suspicious_service"
    SUSPICIOUS_PROCESS = "suspicious_process"
    FILE_SYSTEM_ANOMALY = "file_system_anomaly"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class WindowsThreatEvent:
    """Windows threat event data structure"""
    id: str = field(default_factory=lambda: str(int(time.time() * 1000000)))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    threat_type: WindowsThreatType = WindowsThreatType.SUSPICIOUS_PROCESS
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    source: str = "windows_defender"
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    process_info: Optional[Dict[str, Any]] = None
    file_info: Optional[Dict[str, Any]] = None
    registry_info: Optional[Dict[str, Any]] = None
    mitigation_suggestions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['threat_type'] = self.threat_type.value
        data['severity'] = self.severity.value
        return data


class ScheduledTaskAnalyzer:
    """Analyze suspicious scheduled tasks (DEFENSIVE ONLY)"""
    
    def __init__(self):
        self.enabled = os.getenv("SCHEDULED_TASK_ANALYZER_ENABLED", "true").lower() == "true"
        
        # Suspicious task patterns
        self.suspicious_patterns = [
            r".*\.exe.*-enc",  # Encoded commands
            r".*\.exe.*-nop",  # No profile
            r".*\.exe.*-w hidden",  # Hidden window
            r".*\.exe.*bypass",  # Bypass execution policy
            r".*powershell.*-enc",
            r".*powershell.*-nop",
            r".*powershell.*-w hidden",
            r".*cmd\.exe.*\/c",
            r".*rundll32\.exe.*javascript",
            r".*wscript\.exe.*\/\/e",
            r".*mshta\.exe.*javascript"
        ]
        
        # Suspicious task names
        self.suspicious_names = [
            "update", "upgrade", "maintenance", "system", "security",
            "backup", "cleanup", "scan", "check", "verify", "windows",
            "microsoft", "defender", "security", "update"
        ]
        
        logger.info("Scheduled task analyzer initialized", enabled=self.enabled)
    
    async def analyze_scheduled_tasks(self) -> List[WindowsThreatEvent]:
        """Analyze scheduled tasks for suspicious activity"""
        if not self.enabled or os.name != 'nt':
            return []
        
        threats = []
        
        try:
            # Get scheduled tasks using schtasks
            result = await self._run_schtasks_query()
            
            if result and result.returncode == 0:
                tasks = self._parse_schtasks_output(result.stdout)
                
                for task in tasks:
                    threat = self._analyze_task(task)
                    if threat:
                        threats.append(threat)
                        await self._log_windows_threat(threat)
        
        except Exception as e:
            logger.error("Scheduled task analysis failed", error=str(e))
        
        return threats
    
    async def _run_schtasks_query(self):
        """Run schtasks query command"""
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                result = await loop.run_in_executor(
                    executor,
                    lambda: subprocess.run(
                        ["schtasks", "/query", "/fo", "list", "/v"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                )
            return result
        except Exception as e:
            logger.error("schtasks query failed", error=str(e))
            return None
    
    def _parse_schtasks_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse schtasks output into structured data"""
        tasks = []
        current_task = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if not line:
                if current_task:
                    tasks.append(current_task)
                    current_task = {}
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                current_task[key.strip()] = value.strip()
        
        if current_task:
            tasks.append(current_task)
        
        return tasks
    
    def _analyze_task(self, task: Dict[str, Any]) -> Optional[WindowsThreatEvent]:
        """Analyze individual scheduled task"""
        task_name = task.get("TaskName", "").lower()
        task_to_run = task.get("Task To Run", "").lower()
        
        # Check for suspicious patterns
        suspicious_patterns = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, task_to_run, re.IGNORECASE):
                suspicious_patterns.append(pattern)
        
        # Check for suspicious names
        suspicious_name = any(name in task_name for name in self.suspicious_names)
        
        if not suspicious_patterns and not suspicious_name:
            return None
        
        # Determine severity
        if any("enc" in pattern for pattern in suspicious_patterns):
            severity = ThreatSeverity.HIGH
            confidence = 0.9
        elif any("hidden" in pattern for pattern in suspicious_patterns):
            severity = ThreatSeverity.HIGH
            confidence = 0.8
        elif len(suspicious_patterns) >= 2:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.7
        else:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.6
        
        return WindowsThreatEvent(
            threat_type=WindowsThreatType.SUSPICIOUS_SCHEDULED_TASK,
            severity=severity,
            description=f"Suspicious scheduled task detected: {task_name}",
            details={
                "task_name": task.get("TaskName"),
                "task_to_run": task.get("Task To Run"),
                "run_as_user": task.get("Run As User"),
                "schedule": task.get("Schedule"),
                "status": task.get("Status")
            },
            evidence={
                "suspicious_patterns": suspicious_patterns,
                "suspicious_name": suspicious_name,
                "task_content": task_to_run[:500]  # Limit length
            },
            confidence=confidence,
            mitigation_suggestions=[
                "Review task purpose and legitimacy",
                "Check task author and creation time",
                "Verify task command arguments",
                "Consider disabling unauthorized tasks"
            ]
        )
    
    async def _log_windows_threat(self, threat: WindowsThreatEvent):
        """Log Windows threat event"""
        log_security_event(
            "windows_threat_detected",
            {
                "threat_id": threat.id,
                "threat_type": threat.threat_type.value,
                "severity": threat.severity.value,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


class RegistryAnalyzer:
    """Analyze registry for suspicious autoruns (DEFENSIVE ONLY)"""
    
    def __init__(self):
        self.enabled = os.getenv("REGISTRY_ANALYZER_ENABLED", "true").lower() == "true"
        
        # Registry autorun locations
        self.autorun_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        ]
        
        # Suspicious registry patterns
        self.suspicious_patterns = [
            r"powershell.*-enc",
            r"powershell.*-nop",
            r"powershell.*-w hidden",
            r"cmd\.exe.*\/c",
            r"rundll32\.exe",
            r"regsvr32\.exe",
            r"mshta\.exe",
            r"wscript\.exe",
            r"cscript\.exe",
            r"bitsadmin\.exe"
        ]
        
        logger.info("Registry analyzer initialized", enabled=self.enabled)
    
    async def analyze_registry_autoruns(self) -> List[WindowsThreatEvent]:
        """Analyze registry autoruns for suspicious entries"""
        if not self.enabled or os.name != 'nt':
            return []
        
        threats = []
        
        try:
            import winreg
            
            for key_path in self.autorun_keys:
                try:
                    # Parse registry key
                    if key_path.startswith("HKLM"):
                        root_key = winreg.HKEY_LOCAL_MACHINE
                        sub_key = key_path[5:]
                    elif key_path.startswith("HKCU"):
                        root_key = winreg.HKEY_CURRENT_USER
                        sub_key = key_path[5:]
                    else:
                        continue
                    
                    # Open registry key
                    with winreg.OpenKey(root_key, sub_key) as key:
                        # Enumerate values
                        i = 0
                        while True:
                            try:
                                name, value, reg_type = winreg.EnumValue(key, i)
                                
                                # Analyze registry value
                                threat = self._analyze_registry_value(
                                    name, value, reg_type, key_path
                                )
                                
                                if threat:
                                    threats.append(threat)
                                    await self._log_windows_threat(threat)
                                
                                i += 1
                            except WindowsError:
                                break
                
                except Exception as e:
                    logger.debug(f"Cannot access registry key {key_path}: {e}")
        
        except ImportError:
            logger.warning("winreg module not available")
        except Exception as e:
            logger.error("Registry analysis failed", error=str(e))
        
        return threats
    
    def _analyze_registry_value(self, name: str, value: Any, reg_type: int, 
                              key_path: str) -> Optional[WindowsThreatEvent]:
        """Analyze registry value for suspicious patterns"""
        if reg_type not in [winreg.REG_SZ, winreg.REG_EXPAND_SZ]:
            return None
        
        value_str = str(value).lower()
        
        # Check for suspicious patterns
        suspicious_patterns = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, value_str, re.IGNORECASE):
                suspicious_patterns.append(pattern)
        
        if not suspicious_patterns:
            return None
        
        # Determine severity
        if any("enc" in pattern for pattern in suspicious_patterns):
            severity = ThreatSeverity.HIGH
            confidence = 0.8
        elif len(suspicious_patterns) >= 2:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.7
        else:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.6
        
        return WindowsThreatEvent(
            threat_type=WindowsThreatType.REGISTRY_AUTORUN,
            severity=severity,
            description=f"Suspicious registry autorun: {name}",
            details={
                "registry_key": key_path,
                "value_name": name,
                "value_data": str(value)[:200],  # Limit length
                "reg_type": reg_type
            },
            evidence={
                "suspicious_patterns": suspicious_patterns,
                "value_content": value_str[:500]  # Limit length
            },
            confidence=confidence,
            registry_info={
                "key": key_path,
                "value": name,
                "type": reg_type
            },
            mitigation_suggestions=[
                "Verify legitimacy of registry entry",
                "Check file existence and signature",
                "Review program installation source",
                "Consider removing unauthorized entries"
            ]
        )
    
    async def _log_windows_threat(self, threat: WindowsThreatEvent):
        """Log Windows threat event"""
        log_security_event(
            "windows_threat_detected",
            {
                "threat_id": threat.id,
                "threat_type": threat.threat_type.value,
                "severity": threat.severity.value,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


class PowerShellAnalyzer:
    """Analyze suspicious PowerShell activity (DEFENSIVE ONLY)"""
    
    def __init__(self):
        self.enabled = os.getenv("POWERSHELL_ANALYZER_ENABLED", "true").lower() == "true"
        
        # Suspicious PowerShell patterns
        self.suspicious_patterns = [
            r"-enc.*[A-Za-z0-9+/]{20,}={0,2}",  # Base64 encoded commands
            r"-nop",  # No profile
            r"-w hidden",  # Window hidden
            r"-bypass",  # Execution policy bypass
            r"-executionpolicy.*bypass",
            r"frombase64string",
            r"iex.*\(",
            r"invoke-expression",
            r"start-process.*-windowstyle hidden",
            r"new-object.*system\.diagnostics\.process",
            r"\[system\.text\.encoding\]::utf8\.getstring",
            r"convertto-securestring",
            r"get-wmiobject",
            r"invoke-wmimethod"
        ]
        
        # Suspicious PowerShell commands
        self.suspicious_commands = [
            "downloadstring", "invoke-mimikatz", "get-credential",
            "convertto-securestring", "invoke-expression", "start-process",
            "new-item", "remove-item", "copy-item", "move-item"
        ]
        
        logger.info("PowerShell analyzer initialized", enabled=self.enabled)
    
    async def analyze_powershell_processes(self) -> List[WindowsThreatEvent]:
        """Analyze PowerShell processes for suspicious activity"""
        if not self.enabled:
            return []
        
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    process_name = proc.info['name'].lower() if proc.info['name'] else ""
                    
                    if "powershell" in process_name:
                        cmdline = " ".join(proc.info['cmdline'] or [])
                        
                        threat = self._analyze_powershell_command(
                            proc.info['pid'], cmdline, proc.info.get('username')
                        )
                        
                        if threat:
                            threats.append(threat)
                            await self._log_windows_threat(threat)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error("PowerShell analysis failed", error=str(e))
        
        return threats
    
    def _analyze_powershell_command(self, pid: int, cmdline: str, username: str = None) -> Optional[WindowsThreatEvent]:
        """Analyze PowerShell command for suspicious patterns"""
        cmdline_lower = cmdline.lower()
        
        # Check for suspicious patterns
        detected_patterns = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, cmdline_lower, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        # Check for suspicious commands
        detected_commands = []
        for command in self.suspicious_commands:
            if command in cmdline_lower:
                detected_commands.append(command)
        
        if not detected_patterns and not detected_commands:
            return None
        
        # Determine severity
        if any("enc" in pattern for pattern in detected_patterns):
            severity = ThreatSeverity.HIGH
            confidence = 0.9
        elif any("hidden" in pattern for pattern in detected_patterns):
            severity = ThreatSeverity.HIGH
            confidence = 0.8
        elif len(detected_patterns) >= 2:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.7
        else:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.6
        
        return WindowsThreatEvent(
            threat_type=WindowsThreatType.ENCODED_POWERSHELL,
            severity=severity,
            description=f"Suspicious PowerShell activity detected",
            details={
                "pid": pid,
                "username": username,
                "command_line": cmdline[:500],  # Limit length
                "detected_patterns": detected_patterns,
                "detected_commands": detected_commands
            },
            evidence={
                "suspicious_patterns": detected_patterns,
                "suspicious_commands": detected_commands,
                "full_command": cmdline[:1000]  # Limit length
            },
            confidence=confidence,
            process_info={
                "pid": pid,
                "name": "powershell",
                "username": username,
                "command_line": cmdline
            },
            mitigation_suggestions=[
                "Investigate PowerShell command purpose",
                "Check script execution policy",
                "Verify user authorization",
                "Review command arguments for obfuscation"
            ]
        )
    
    async def _log_windows_threat(self, threat: WindowsThreatEvent):
        """Log Windows threat event"""
        log_security_event(
            "windows_threat_detected",
            {
                "threat_id": threat.id,
                "threat_type": threat.threat_type.value,
                "severity": threat.severity.value,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


class StartupAnalyzer:
    """Analyze startup folder persistence (DEFENSIVE ONLY)"""
    
    def __init__(self):
        self.enabled = os.getenv("STARTUP_ANALYZER_ENABLED", "true").lower() == "true"
        
        # Startup folders
        self.startup_folders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
            os.path.expandvars(r"%USERPROFILE%\Start Menu\Programs\Startup")
        ]
        
        # Suspicious file extensions
        self.suspicious_extensions = [".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr"]
        
        # Suspicious file names
        self.suspicious_names = [
            "update", "upgrade", "maintenance", "system", "security",
            "backup", "cleanup", "temp", "tmp", "cache", "windows",
            "microsoft", "defender", "svchost", "explorer"
        ]
        
        logger.info("Startup analyzer initialized", enabled=self.enabled)
    
    async def analyze_startup_folders(self) -> List[WindowsThreatEvent]:
        """Analyze startup folders for suspicious files"""
        if not self.enabled or os.name != 'nt':
            return []
        
        threats = []
        
        try:
            for startup_folder in self.startup_folders:
                if not os.path.exists(startup_folder):
                    continue
                
                for file_path in os.listdir(startup_folder):
                    full_path = os.path.join(startup_folder, file_path)
                    
                    if os.path.isfile(full_path):
                        threat = self._analyze_startup_file(full_path)
                        
                        if threat:
                            threats.append(threat)
                            await self._log_windows_threat(threat)
        
        except Exception as e:
            logger.error("Startup folder analysis failed", error=str(e))
        
        return threats
    
    def _analyze_startup_file(self, file_path: str) -> Optional[WindowsThreatEvent]:
        """Analyze startup file for suspicious characteristics"""
        file_name = os.path.basename(file_path).lower()
        file_ext = os.path.splitext(file_name)[1]
        
        # Check file extension
        if file_ext not in self.suspicious_extensions:
            return None
        
        # Check file name
        suspicious_name = any(pattern in file_name for pattern in self.suspicious_names)
        
        # Check file content for suspicious patterns
        suspicious_content = False
        content_patterns = []
        
        try:
            if file_ext in [".bat", ".cmd", ".ps1", ".vbs", ".js"]:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                
                # Check for suspicious patterns
                dangerous_patterns = [
                    "powershell", "cmd.exe", "wscript", "rundll32",
                    "-enc", "-nop", "-w hidden", "bypass",
                    "download", "invoke-expression", "iex",
                    "start-process", "new-object"
                ]
                
                for pattern in dangerous_patterns:
                    if pattern in content:
                        content_patterns.append(pattern)
                        suspicious_content = True
        
        except Exception:
            pass
        
        # Determine if file is suspicious
        if not (suspicious_content or suspicious_name or file_ext in [".ps1", ".vbs", ".js"]):
            return None
        
        # Determine severity
        if suspicious_content and file_ext in [".ps1", ".bat", ".cmd"]:
            severity = ThreatSeverity.HIGH
            confidence = 0.8
        elif suspicious_name and file_ext in [".ps1", ".bat", ".cmd"]:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.7
        else:
            severity = ThreatSeverity.MEDIUM
            confidence = 0.6
        
        return WindowsThreatEvent(
            threat_type=WindowsThreatType.STARTUP_PERSISTENCE,
            severity=severity,
            description=f"Suspicious startup file detected: {file_name}",
            details={
                "file_path": file_path,
                "file_name": file_name,
                "file_extension": file_ext,
                "suspicious_name": suspicious_name,
                "suspicious_content": suspicious_content
            },
            evidence={
                "content_patterns": content_patterns,
                "file_exists": os.path.exists(file_path),
                "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
            },
            confidence=confidence,
            file_info={
                "path": file_path,
                "name": file_name,
                "extension": file_ext
            },
            mitigation_suggestions=[
                "Verify file legitimacy and purpose",
                "Check file signature and publisher",
                "Review file creation time and source",
                "Consider removing unauthorized startup files"
            ]
        )
    
    async def _log_windows_threat(self, threat: WindowsThreatEvent):
        """Log Windows threat event"""
        log_security_event(
            "windows_threat_detected",
            {
                "threat_id": threat.id,
                "threat_type": threat.threat_type.value,
                "severity": threat.severity.value,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


class WindowsDefender:
    """Main Windows defender analyzer (DEFENSIVE ONLY)"""
    
    def __init__(self):
        self.enabled = os.getenv("WINDOWS_DEFENDER_ENABLED", "true").lower() == "true"
        
        # Initialize analyzers
        self.task_analyzer = ScheduledTaskAnalyzer()
        self.registry_analyzer = RegistryAnalyzer()
        self.powershell_analyzer = PowerShellAnalyzer()
        self.startup_analyzer = StartupAnalyzer()
        
        # Threat history
        self.threat_history = deque(maxlen=1000)
        self.threat_stats = defaultdict(int)
        
        # Analysis interval
        self.analysis_interval = int(os.getenv("WINDOWS_ANALYSIS_INTERVAL", "300"))  # 5 minutes
        
        logger.info("Windows defender analyzer initialized", enabled=self.enabled)
    
    async def start_monitoring(self):
        """Start Windows security monitoring"""
        if not self.enabled or os.name != 'nt':
            return
        
        logger.info("Starting Windows security monitoring")
        
        while True:
            try:
                # Run all analyzers
                all_threats = []
                
                # Scheduled task analysis
                task_threats = await self.task_analyzer.analyze_scheduled_tasks()
                all_threats.extend(task_threats)
                
                # Registry analysis
                registry_threats = await self.registry_analyzer.analyze_registry_autoruns()
                all_threats.extend(registry_threats)
                
                # PowerShell analysis
                powershell_threats = await self.powershell_analyzer.analyze_powershell_processes()
                all_threats.extend(powershell_threats)
                
                # Startup folder analysis
                startup_threats = await self.startup_analyzer.analyze_startup_folders()
                all_threats.extend(startup_threats)
                
                # Process threats
                for threat in all_threats:
                    self.threat_history.append(threat)
                    self.threat_stats[threat.threat_type.value] += 1
                
                # Log summary
                if all_threats:
                    logger.info(
                        "Windows security analysis completed",
                        threats_detected=len(all_threats),
                        threat_types=[t.threat_type.value for t in all_threats]
                    )
                
                # Wait for next cycle
                await asyncio.sleep(self.analysis_interval)
                
            except Exception as e:
                logger.error("Windows monitoring error", error=str(e))
                await asyncio.sleep(self.analysis_interval)
    
    def get_windows_threat_summary(self) -> Dict[str, Any]:
        """Get Windows threat detection summary"""
        recent_threats = list(self.threat_history)[-100:]  # Last 100 threats
        
        return {
            "total_threats": len(self.threat_history),
            "recent_threats": len(recent_threats),
            "threat_types": dict(self.threat_stats),
            "last_detection": recent_threats[-1].timestamp.isoformat() if recent_threats else None,
            "enabled": self.enabled,
            "analysis_interval": self.analysis_interval,
            "is_windows": os.name == 'nt',
            "analyzers": {
                "scheduled_tasks": self.task_analyzer.enabled,
                "registry": self.registry_analyzer.enabled,
                "powershell": self.powershell_analyzer.enabled,
                "startup": self.startup_analyzer.enabled
            }
        }
    
    def get_recent_windows_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent Windows threats"""
        recent_threats = self.threat_history[-limit:]
        
        return [
            {
                "id": threat.id,
                "threat_type": threat.threat_type.value,
                "severity": threat.severity.value,
                "timestamp": threat.timestamp.isoformat(),
                "source": threat.source,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence,
                "mitigation_suggestions": threat.mitigation_suggestions
            }
            for threat in recent_threats
        ]


# Global Windows defender instance
windows_defender = WindowsDefender()


async def start_windows_monitoring():
    """Start Windows security monitoring"""
    await windows_defender.start_monitoring()


def get_windows_threat_summary() -> Dict[str, Any]:
    """Get Windows threat detection summary"""
    return windows_defender.get_windows_threat_summary()


def get_recent_windows_threats(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent Windows threats"""
    return windows_defender.get_recent_windows_threats(limit)
