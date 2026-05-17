"""
Windows Hardening Support for Mary V5 Enterprise
Suspicious activity detection for Windows environments
"""

import os
import time
import json
import subprocess
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import psutil
import re

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class WindowsThreatType(Enum):
    """Windows-specific threat types"""
    SUSPICIOUS_SCHEDULED_TASK = "suspicious_scheduled_task"
    REGISTRY_PERSISTENCE = "registry_persistence"
    UNSIGNED_EXECUTABLE = "unsigned_executable"
    STARTUP_FOLDER_ABUSE = "startup_folder_abuse"
    DANGEROUS_POWERSHELL = "dangerous_powershell"
    WMI_PERSISTENCE = "wmi_persistence"
    SUSPICIOUS_SERVICE = "suspicious_service"
    PROCESS_INJECTION = "process_injection"


@dataclass
class WindowsThreatEvent:
    """Windows threat event data"""
    id: str
    type: WindowsThreatType
    severity: str
    timestamp: datetime
    source: str
    description: str
    evidence: Dict[str, Any]
    confidence: float
    process_info: Optional[Dict[str, Any]] = None
    file_info: Optional[Dict[str, Any]] = None


class ScheduledTaskMonitor:
    """Monitor suspicious scheduled tasks"""
    
    def __init__(self):
        self.enabled = os.getenv("SCHEDULED_TASK_MONITOR_ENABLED", "true").lower() == "true"
        
        # Suspicious task patterns
        self.suspicious_task_names = [
            "update", "upgrade", "maintenance", "system", "security",
            "backup", "cleanup", "scan", "check", "verify"
        ]
        
        self.suspicious_commands = [
            "powershell", "cmd.exe", "wscript", "cscript",
            "rundll32", "regsvr32", "mshta", "bitsadmin"
        ]
        
        # Task history
        self.task_history = []
        
        logger.info("Scheduled task monitor initialized", enabled=self.enabled)
    
    async def monitor_scheduled_tasks(self) -> List[WindowsThreatEvent]:
        """Monitor for suspicious scheduled tasks"""
        if not self.enabled or os.name != 'nt':
            return []
        
        threats = []
        
        try:
            # Get scheduled tasks using schtasks
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "list", "/v"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                tasks = self._parse_scheduled_tasks(result.stdout)
                
                for task in tasks:
                    threat = self._analyze_scheduled_task(task)
                    if threat:
                        threats.append(threat)
                        await self._log_windows_threat(threat)
        
        except subprocess.TimeoutExpired:
            logger.error("Scheduled tasks query timeout")
        except Exception as e:
            logger.error("Scheduled task monitoring error", error=str(e))
        
        return threats
    
    def _parse_scheduled_tasks(self, output: str) -> List[Dict[str, Any]]:
        """Parse scheduled tasks output"""
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
    
    def _analyze_scheduled_task(self, task: Dict[str, Any]) -> Optional[WindowsThreatEvent]:
        """Analyze scheduled task for suspicious patterns"""
        task_name = task.get("TaskName", "").lower()
        task_to_run = task.get("Task To Run", "").lower()
        
        # Check for suspicious task names
        suspicious_name = any(pattern in task_name for pattern in self.suspicious_task_names)
        
        # Check for suspicious commands
        suspicious_command = any(cmd in task_to_run for cmd in self.suspicious_commands)
        
        # Check for hidden or obfuscated commands
        hidden_patterns = [
            "-enc", "-nop", "-w hidden", "bypass", "executionpolicy",
            "base64", "frombase64string"
        ]
        
        hidden_command = any(pattern in task_to_run for pattern in hidden_patterns)
        
        # Determine threat level
        if suspicious_command and hidden_command:
            severity = "high"
            confidence = 0.9
        elif suspicious_command:
            severity = "medium"
            confidence = 0.7
        elif suspicious_name and suspicious_command:
            severity = "medium"
            confidence = 0.6
        else:
            return None
        
        return WindowsThreatEvent(
            id=f"task_{int(time.time())}",
            type=WindowsThreatType.SUSPICIOUS_SCHEDULED_TASK,
            severity=severity,
            timestamp=datetime.utcnow(),
            source="scheduled_tasks",
            description=f"Suspicious scheduled task detected: {task_name}",
            evidence={
                "task_name": task.get("TaskName"),
                "task_to_run": task.get("Task To Run"),
                "run_as_user": task.get("Run As User"),
                "schedule": task.get("Schedule"),
                "suspicious_patterns": {
                    "name": suspicious_name,
                    "command": suspicious_command,
                    "hidden": hidden_command
                }
            },
            confidence=confidence
        )
    
    async def _log_windows_threat(self, threat: WindowsThreatEvent):
        """Log Windows threat event"""
        log_security_event(
            "windows_threat_detected",
            {
                "threat_id": threat.id,
                "type": threat.type.value,
                "severity": threat.severity,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


class RegistryPersistenceMonitor:
    """Monitor registry persistence mechanisms"""
    
    def __init__(self):
        self.enabled = os.getenv("REGISTRY_MONITOR_ENABLED", "true").lower() == "true"
        
        # Persistence registry keys
        self.persistence_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        ]
        
        # Suspicious registry values
        self.suspicious_patterns = [
            "powershell", "cmd.exe", "wscript", "cscript",
            "rundll32", "regsvr32", "mshta", "bitsadmin",
            "-enc", "-nop", "-w hidden", "bypass"
        ]
        
        logger.info("Registry persistence monitor initialized", enabled=self.enabled)
    
    async def monitor_registry_persistence(self) -> List[WindowsThreatEvent]:
        """Monitor registry for persistence mechanisms"""
        if not self.enabled or os.name != 'nt':
            return []
        
        threats = []
        
        try:
            import winreg
            
            for key_path in self.persistence_keys:
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
            logger.error("Registry monitoring error", error=str(e))
        
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
            if pattern in value_str:
                suspicious_patterns.append(pattern)
        
        if not suspicious_patterns:
            return None
        
        # Determine severity
        if any(advanced in value_str for advanced in ["-enc", "-nop", "-w hidden"]):
            severity = "high"
            confidence = 0.8
        elif len(suspicious_patterns) >= 2:
            severity = "medium"
            confidence = 0.7
        else:
            severity = "low"
            confidence = 0.6
        
        return WindowsThreatEvent(
            id=f"registry_{int(time.time())}",
            type=WindowsThreatType.REGISTRY_PERSISTENCE,
            severity=severity,
            timestamp=datetime.utcnow(),
            source="registry",
            description=f"Suspicious registry persistence: {name}",
            evidence={
                "registry_key": key_path,
                "value_name": name,
                "value_data": str(value)[:200],  # Limit length
                "reg_type": reg_type,
                "suspicious_patterns": suspicious_patterns
            },
            confidence=confidence
        )


class PowerShellMonitor:
    """Monitor dangerous PowerShell activity"""
    
    def __init__(self):
        self.enabled = os.getenv("POWERSHELL_MONITOR_ENABLED", "true").lower() == "true"
        
        # Dangerous PowerShell patterns
        self.dangerous_patterns = [
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
            r"convertto-securestring"
        ]
        
        logger.info("PowerShell monitor initialized", enabled=self.enabled)
    
    async def monitor_powershell_processes(self) -> List[WindowsThreatEvent]:
        """Monitor for dangerous PowerShell processes"""
        if not self.enabled:
            return []
        
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_name = proc.info['name'].lower() if proc.info['name'] else ""
                    
                    if "powershell" in process_name:
                        cmdline = " ".join(proc.info['cmdline'] or [])
                        
                        threat = self._analyze_powershell_command(
                            proc.info['pid'], cmdline
                        )
                        
                        if threat:
                            threats.append(threat)
                            await self._log_windows_threat(threat)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error("PowerShell monitoring error", error=str(e))
        
        return threats
    
    def _analyze_powershell_command(self, pid: int, cmdline: str) -> Optional[WindowsThreatEvent]:
        """Analyze PowerShell command for dangerous patterns"""
        cmdline_lower = cmdline.lower()
        
        # Check for dangerous patterns
        detected_patterns = []
        for pattern in self.dangerous_patterns:
            if re.search(pattern, cmdline_lower, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        if not detected_patterns:
            return None
        
        # Determine severity
        if any("enc" in pattern for pattern in detected_patterns):
            severity = "high"
            confidence = 0.9
        elif any("hidden" in pattern for pattern in detected_patterns):
            severity = "high"
            confidence = 0.8
        elif len(detected_patterns) >= 2:
            severity = "medium"
            confidence = 0.7
        else:
            severity = "medium"
            confidence = 0.6
        
        return WindowsThreatEvent(
            id=f"powershell_{pid}_{int(time.time())}",
            type=WindowsThreatType.DANGEROUS_POWERSHELL,
            severity=severity,
            timestamp=datetime.utcnow(),
            source="process_monitor",
            description=f"Dangerous PowerShell activity detected",
            evidence={
                "pid": pid,
                "command_line": cmdline[:500],  # Limit length
                "detected_patterns": detected_patterns
            },
            confidence=confidence,
            process_info={
                "pid": pid,
                "name": "powershell",
                "cmdline": cmdline
            }
        )


class StartupFolderMonitor:
    """Monitor startup folder abuse"""
    
    def __init__(self):
        self.enabled = os.getenv("STARTUP_FOLDER_MONITOR_ENABLED", "true").lower() == "true"
        
        # Startup folders
        self.startup_folders = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
            os.path.expandvars(r"%USERPROFILE%\Start Menu\Programs\Startup")
        ]
        
        # Suspicious file patterns
        self.suspicious_extensions = [".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"]
        self.suspicious_names = [
            "update", "upgrade", "maintenance", "system", "security",
            "backup", "cleanup", "temp", "tmp", "cache"
        ]
        
        logger.info("Startup folder monitor initialized", enabled=self.enabled)
    
    async def monitor_startup_folders(self) -> List[WindowsThreatEvent]:
        """Monitor startup folders for suspicious files"""
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
            logger.error("Startup folder monitoring error", error=str(e))
        
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
        try:
            if file_ext in [".bat", ".cmd", ".ps1", ".vbs", ".js"]:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                
                suspicious_patterns = [
                    "powershell", "cmd.exe", "wscript", "rundll32",
                    "-enc", "-nop", "-w hidden", "bypass",
                    "download", "invoke-expression", "iex"
                ]
                
                suspicious_content = any(pattern in content for pattern in suspicious_patterns)
        
        except Exception:
            pass
        
        # Determine if file is suspicious
        if suspicious_content or (suspicious_name and file_ext in [".bat", ".cmd", ".ps1"]):
            severity = "medium"
            confidence = 0.7
        elif file_ext in [".ps1", ".vbs", ".js"]:
            severity = "low"
            confidence = 0.6
        else:
            return None
        
        return WindowsThreatEvent(
            id=f"startup_{int(time.time())}",
            type=WindowsThreatType.STARTUP_FOLDER_ABUSE,
            severity=severity,
            timestamp=datetime.utcnow(),
            source="startup_folder",
            description=f"Suspicious startup file detected: {file_name}",
            evidence={
                "file_path": file_path,
                "file_name": file_name,
                "file_extension": file_ext,
                "suspicious_name": suspicious_name,
                "suspicious_content": suspicious_content
            },
            confidence=confidence,
            file_info={
                "path": file_path,
                "name": file_name,
                "extension": file_ext
            }
        )


class WindowsHardeningEngine:
    """Main Windows hardening engine"""
    
    def __init__(self):
        self.enabled = os.getenv("WINDOWS_HARDENING_ENABLED", "true").lower() == "true"
        
        # Initialize monitors
        self.task_monitor = ScheduledTaskMonitor()
        self.registry_monitor = RegistryPersistenceMonitor()
        self.powershell_monitor = PowerShellMonitor()
        self.startup_monitor = StartupFolderMonitor()
        
        # Threat history
        self.threat_history = []
        self.threat_stats = defaultdict(int)
        
        # Monitoring interval
        self.monitoring_interval = int(os.getenv("WINDOWS_MONITORING_INTERVAL", "60"))  # 1 minute
        
        logger.info("Windows hardening engine initialized", enabled=self.enabled)
    
    async def start_monitoring(self):
        """Start Windows security monitoring"""
        if not self.enabled or os.name != 'nt':
            return
        
        logger.info("Starting Windows security monitoring")
        
        while True:
            try:
                # Run all monitors
                all_threats = []
                
                # Scheduled task monitoring
                task_threats = await self.task_monitor.monitor_scheduled_tasks()
                all_threats.extend(task_threats)
                
                # Registry monitoring
                registry_threats = await self.registry_monitor.monitor_registry_persistence()
                all_threats.extend(registry_threats)
                
                # PowerShell monitoring
                powershell_threats = await self.powershell_monitor.monitor_powershell_processes()
                all_threats.extend(powershell_threats)
                
                # Startup folder monitoring
                startup_threats = await self.startup_monitor.monitor_startup_folders()
                all_threats.extend(startup_threats)
                
                # Process threats
                for threat in all_threats:
                    self.threat_history.append(threat)
                    self.threat_stats[threat.type.value] += 1
                
                # Log summary
                if all_threats:
                    logger.info(
                        "Windows threat detection cycle completed",
                        threats_detected=len(all_threats),
                        threat_types=[t.type.value for t in all_threats]
                    )
                
                # Wait for next cycle
                await asyncio.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error("Windows monitoring error", error=str(e))
                await asyncio.sleep(self.monitoring_interval)
    
    def get_windows_threat_summary(self) -> Dict[str, Any]:
        """Get Windows threat detection summary"""
        recent_threats = self.threat_history[-100:]  # Last 100 threats
        
        return {
            "total_threats": len(self.threat_history),
            "recent_threats": len(recent_threats),
            "threat_types": dict(self.threat_stats),
            "last_detection": recent_threats[-1].timestamp.isoformat() if recent_threats else None,
            "enabled": self.enabled,
            "monitoring_interval": self.monitoring_interval,
            "is_windows": os.name == 'nt'
        }
    
    def get_recent_windows_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent Windows threats"""
        recent_threats = self.threat_history[-limit:]
        
        return [
            {
                "id": threat.id,
                "type": threat.type.value,
                "severity": threat.severity,
                "timestamp": threat.timestamp.isoformat(),
                "source": threat.source,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
            for threat in recent_threats
        ]
    
    async def _log_windows_threat(self, threat: WindowsThreatEvent):
        """Log Windows threat event"""
        log_security_event(
            "windows_threat_detected",
            {
                "threat_id": threat.id,
                "type": threat.type.value,
                "severity": threat.severity,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


# Global Windows hardening engine
windows_hardening_engine = WindowsHardeningEngine()


def get_windows_hardening_engine() -> WindowsHardeningEngine:
    """Get global Windows hardening engine"""
    return windows_hardening_engine


async def start_windows_monitoring():
    """Start Windows security monitoring"""
    await windows_hardening_engine.start_monitoring()


def get_windows_threat_summary() -> Dict[str, Any]:
    """Get Windows threat detection summary"""
    return windows_hardening_engine.get_windows_threat_summary()


def get_recent_windows_threats(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent Windows threats"""
    return windows_hardening_engine.get_recent_windows_threats(limit)
