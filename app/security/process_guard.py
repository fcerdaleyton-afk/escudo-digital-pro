"""
MARY V5 SHIELD CORE - Process Isolation Layer
DEFENSIVE ONLY: Monitor dangerous subprocess execution, detect suspicious patterns
"""

import os
import sys
import time
import asyncio
import subprocess
import threading
import signal
import psutil
import hashlib
import json
import re
from typing import Dict, List, Optional, Any, Set, Callable, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
import weakref

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger
from app.core.security_settings import get_security_settings


class ProcessRiskLevel(Enum):
    """Process risk levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"


class ProcessViolationType(Enum):
    """Process violation types (DEFENSIVE ONLY)"""
    SUSPICIOUS_COMMAND = "suspicious_command"
    ENCODED_POWERSHELL = "encoded_powershell"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DANGEROUS_EXECUTABLE = "dangerous_executable"
    SUSPICIOUS_CHILD_PROCESS = "suspicious_child_process"
    MALICIOUS_PATTERN = "malicious_pattern"
    RESOURCE_ABUSE = "resource_abuse"
    UNAUTHORIZED_EXECUTION = "unauthorized_execution"


@dataclass
class ProcessEvent:
    """Process event data structure"""
    id: str = field(default_factory=lambda: str(int(time.time() * 1000000)))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    pid: int
    parent_pid: Optional[int] = None
    command: str = ""
    executable: str = ""
    arguments: List[str] = field(default_factory=list)
    user: Optional[str] = None
    risk_level: ProcessRiskLevel = ProcessRiskLevel.LOW
    violation_type: Optional[ProcessViolationType] = None
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    terminated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['risk_level'] = self.risk_level.value
        if self.violation_type:
            data['violation_type'] = self.violation_type.value
        return data


class SuspiciousPatternDetector:
    """Detect suspicious patterns in process execution"""
    
    def __init__(self):
        self.enabled = os.getenv("SUSPICIOUS_PATTERN_DETECTOR_ENABLED", "true").lower() == "true"
        
        # Suspicious command patterns (DEFENSIVE ONLY)
        self.suspicious_patterns = [
            # PowerShell encoded commands
            r"powershell.*-enc\s+[A-Za-z0-9+/]{20,}={0,2}",
            r"powershell.*-nop",
            r"powershell.*-w\s+hidden",
            r"powershell.*-bypass",
            r"powershell.*-executionpolicy.*bypass",
            r"powershell.*frombase64string",
            r"powershell.*invoke-expression",
            r"powershell.*iex\s*\(",
            
            # CMD suspicious patterns
            r"cmd\.exe.*\/c",
            r"cmd\.exe.*\/k",
            r"cmd\.exe.*echo.*\|",
            r"cmd\.exe.*for.*\/f",
            
            # Suspicious executables
            r"rundll32\.exe.*javascript",
            r"rundll32\.exe.*shell32\.dll",
            r"regsvr32\.exe.*\.scf",
            r"regsvr32\.exe.*\.js",
            r"mshta\.exe.*javascript",
            r"wscript\.exe.*\/\/e",
            r"cscript\.exe.*\/\/e",
            r"bitsadmin\.exe.*\/transfer",
            
            # Download patterns
            r"curl.*-o.*\.(exe|scr|bat|cmd|ps1|vbs)",
            r"wget.*-O.*\.(exe|scr|bat|cmd|ps1|vbs)",
            r"certutil.*-urlcache",
            r"bitsadmin.*download",
            
            # Registry manipulation
            r"reg\s+add",
            r"reg\s+delete",
            r"reg\s+copy",
            
            # System manipulation
            r"sc\s+create",
            r"sc\s+start",
            r"sc\s+config",
            r"net\s+user",
            r"net\s+localgroup",
            
            # File system suspicious operations
            r"attrib\s+\+h",
            r"icacls.*\/grant",
            r"takeown.*\/f",
            
            # Network suspicious operations
            r"netsh.*portproxy",
            r"netsh.*firewall",
            r"route.*add",
        ]
        
        # Dangerous executables list
        self.dangerous_executables = {
            "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
            "mshta.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe",
            "certutil.exe", "wmic.exe", "netsh.exe", "schtasks.exe",
            "at.exe", "taskkill.exe", "timeout.exe", "choice.exe"
        }
        
        # Encoded command patterns
        self.encoded_patterns = [
            r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64
            r"\\x[0-9a-fA-F]{2}",        # Hex encoding
            r"%[0-9a-fA-F]{2}",           # URL encoding
        ]
        
        # Privilege escalation patterns
        self.privilege_escalation_patterns = [
            r"runas",
            r"sudo",
            r"su\s-",
            r"psexec.*-s",
            r"powershell.*-verb.*runas",
        ]
        
        self.logger = get_structured_logger("suspicious_pattern_detector")
        
        self.logger.info("Suspicious pattern detector initialized", enabled=self.enabled)
    
    def analyze_command(self, command: str, executable: str, arguments: List[str]) -> Tuple[ProcessRiskLevel, Optional[ProcessViolationType], str]:
        """Analyze command for suspicious patterns"""
        if not self.enabled:
            return ProcessRiskLevel.LOW, None, "Pattern detection disabled"
        
        full_command = f"{executable} {' '.join(arguments)}"
        full_command_lower = full_command.lower()
        
        risk_score = 0.0
        detected_patterns = []
        violation_type = None
        description = ""
        
        # Check against suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, full_command_lower, re.IGNORECASE):
                risk_score += 0.3
                detected_patterns.append(pattern)
                description += f"Suspicious pattern detected: {pattern}. "
        
        # Check dangerous executables
        if os.path.basename(executable).lower() in self.dangerous_executables:
            risk_score += 0.4
            detected_patterns.append(f"Dangerous executable: {executable}")
            description += f"Use of dangerous executable: {os.path.basename(executable)}. "
        
        # Check for encoded commands
        for pattern in self.encoded_patterns:
            if re.search(pattern, full_command_lower):
                risk_score += 0.5
                detected_patterns.append(f"Encoded command: {pattern}")
                description += "Encoded command detected. "
                violation_type = ProcessViolationType.ENCODED_POWERSHELL
        
        # Check privilege escalation
        for pattern in self.privilege_escalation_patterns:
            if re.search(pattern, full_command_lower):
                risk_score += 0.4
                detected_patterns.append(f"Privilege escalation: {pattern}")
                description += "Privilege escalation attempt detected. "
                violation_type = ProcessViolationType.PRIVILEGE_ESCALATION
        
        # Check for PowerShell specific patterns
        if "powershell" in executable.lower() or any("powershell" in arg.lower() for arg in arguments):
            if any("-enc" in arg.lower() for arg in arguments):
                risk_score += 0.6
                detected_patterns.append("PowerShell encoded command")
                description += "PowerShell encoded command detected. "
                violation_type = ProcessViolationType.ENCODED_POWERSHELL
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = ProcessRiskLevel.CRITICAL
            if not violation_type:
                violation_type = ProcessViolationType.SUSPICIOUS_COMMAND
        elif risk_score >= 0.6:
            risk_level = ProcessRiskLevel.HIGH
            if not violation_type:
                violation_type = ProcessViolationType.SUSPICIOUS_COMMAND
        elif risk_score >= 0.3:
            risk_level = ProcessRiskLevel.MEDIUM
            if not violation_type:
                violation_type = ProcessViolationType.SUSPICIOUS_COMMAND
        else:
            risk_level = ProcessRiskLevel.LOW
        
        if not description:
            description = "Command analysis completed"
        
        return risk_level, violation_type, description


class ProcessMonitor:
    """Monitor running processes for suspicious activity"""
    
    def __init__(self):
        self.enabled = os.getenv("PROCESS_MONITOR_ENABLED", "true").lower() == "true"
        
        # Monitoring interval
        self.monitoring_interval = int(os.getenv("PROCESS_MONITORING_INTERVAL", "30"))  # seconds
        
        # Process tracking
        self.monitored_processes: Dict[int, Dict[str, Any]] = {}
        self.process_events: deque = deque(maxlen=10000)
        
        # Statistics
        self.monitoring_stats = {
            "processes_monitored": 0,
            "violations_detected": 0,
            "processes_terminated": 0,
            "by_risk_level": defaultdict(int),
            "by_violation_type": defaultdict(int)
        }
        
        self.logger = get_structured_logger("process_monitor")
        
        # Start monitoring
        self._monitoring_task = None
        
        self.logger.info("Process monitor initialized", enabled=self.enabled)
    
    async def start_monitoring(self):
        """Start process monitoring"""
        if not self.enabled:
            return
        
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self.logger.info("Process monitoring started")
    
    async def stop_monitoring(self):
        """Stop process monitoring"""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Process monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                await self._scan_processes()
                await asyncio.sleep(self.monitoring_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Process monitoring error", error=str(e))
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _scan_processes(self):
        """Scan all running processes"""
        try:
            current_pids = set()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid']):
                try:
                    current_pids.add(proc.info['pid'])
                    
                    # Check if this is a new process
                    if proc.info['pid'] not in self.monitored_processes:
                        await self._monitor_new_process(proc)
                    
                    # Update process information
                    self.monitored_processes[proc.info['pid']] = {
                        'last_seen': datetime.utcnow(),
                        'name': proc.info['name'],
                        'exe': proc.info['exe'],
                        'cmdline': proc.info['cmdline'],
                        'username': proc.info['username'],
                        'ppid': proc.info['ppid']
                    }
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Clean up dead processes
            dead_pids = set(self.monitored_processes.keys()) - current_pids
            for pid in dead_pids:
                del self.monitored_processes[pid]
            
            self.monitoring_stats["processes_monitored"] = len(current_pids)
            
        except Exception as e:
            self.logger.error("Process scan error", error=str(e))
    
    async def _monitor_new_process(self, proc):
        """Monitor new process for suspicious activity"""
        try:
            executable = proc.info.get('exe', '')
            command_line = proc.info.get('cmdline', [])
            username = proc.info.get('username', '')
            parent_pid = proc.info.get('ppid')
            
            if not executable or not command_line:
                return
            
            # Analyze command
            pattern_detector = SuspiciousPatternDetector()
            risk_level, violation_type, description = pattern_detector.analyze_command(
                ' '.join(command_line), executable, command_line
            )
            
            # Create process event
            event = ProcessEvent(
                pid=proc.info['pid'],
                parent_pid=parent_pid,
                command=' '.join(command_line),
                executable=executable,
                arguments=command_line[1:] if len(command_line) > 1 else [],
                user=username,
                risk_level=risk_level,
                violation_type=violation_type,
                description=description,
                details={
                    'process_name': proc.info.get('name', ''),
                    'parent_name': self._get_process_name(parent_pid) if parent_pid else None,
                    'command_line_length': len(' '.join(command_line))
                }
            )
            
            # Store event
            self.process_events.append(event)
            
            # Update statistics
            self.monitoring_stats["violations_detected"] += 1
            self.monitoring_stats["by_risk_level"][risk_level.value] += 1
            if violation_type:
                self.monitoring_stats["by_violation_type"][violation_type.value] += 1
            
            # Log suspicious processes
            if risk_level in [ProcessRiskLevel.HIGH, ProcessRiskLevel.CRITICAL]:
                self.logger.warning(
                    "Suspicious process detected",
                    pid=proc.info['pid'],
                    executable=executable,
                    risk_level=risk_level.value,
                    violation_type=violation_type.value if violation_type else None,
                    description=description
                )
            
            # Take action for critical processes
            if risk_level == ProcessRiskLevel.CRITICAL:
                await self._handle_critical_process(event)
        
        except Exception as e:
            self.logger.error("Process monitoring error", error=str(e))
    
    def _get_process_name(self, pid: int) -> Optional[str]:
        """Get process name by PID"""
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    async def _handle_critical_process(self, event: ProcessEvent):
        """Handle critical risk processes"""
        try:
            # In defensive mode, we only monitor and alert
            # No termination or blocking actions
            
            self.logger.critical(
                "Critical process detected - DEFENSIVE MONITORING ONLY",
                pid=event.pid,
                executable=event.executable,
                command=event.command,
                risk_level=event.risk_level.value,
                description=event.description
            )
            
            # Could add additional defensive actions like:
            # - Alert to security team
            # - Log to SIEM
            # - Increase monitoring frequency
            # - Quarantine user session
            
        except Exception as e:
            self.logger.error("Critical process handling error", error=str(e))
    
    def get_process_events(self, limit: int = 100, risk_level: Optional[ProcessRiskLevel] = None) -> List[ProcessEvent]:
        """Get process events"""
        events = list(self.process_events)
        
        if risk_level:
            events = [e for e in events if e.risk_level == risk_level]
        
        # Return most recent events
        return events[-limit:] if len(events) > limit else events
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            "enabled": self.enabled,
            "monitoring_interval": self.monitoring_interval,
            "processes_monitored": self.monitoring_stats["processes_monitored"],
            "violations_detected": self.monitoring_stats["violations_detected"],
            "processes_terminated": self.monitoring_stats["processes_terminated"],
            "by_risk_level": dict(self.monitoring_stats["by_risk_level"]),
            "by_violation_type": dict(self.monitoring_stats["by_violation_type"])
        }


class ProcessGuard:
    """Main process guard system (DEFENSIVE ONLY)"""
    
    def __init__(self):
        self.enabled = os.getenv("PROCESS_GUARD_ENABLED", "true").lower() == "true"
        
        # Components
        self.pattern_detector = SuspiciousPatternDetector()
        self.process_monitor = ProcessMonitor()
        
        # Process execution tracking
        self.execution_history: Dict[str, List[ProcessEvent]] = defaultdict(list)
        self.blocked_commands: Set[str] = set()
        
        # Statistics
        self.guard_stats = {
            "executions_monitored": 0,
            "executions_blocked": 0,
            "violations_detected": 0,
            "alerts_generated": 0
        }
        
        # Event handlers
        self.event_handlers: List[Callable[[ProcessEvent], None]] = []
        
        self.logger = get_structured_logger("process_guard")
        
        self.logger.info("Process guard initialized", enabled=self.enabled)
    
    async def start(self):
        """Start process guard"""
        if not self.enabled:
            return
        
        await self.process_monitor.start_monitoring()
        self.logger.info("Process guard started")
    
    async def stop(self):
        """Stop process guard"""
        if not self.enabled:
            return
        
        await self.process_monitor.stop_monitoring()
        self.logger.info("Process guard stopped")
    
    def register_event_handler(self, handler: Callable[[ProcessEvent], None]):
        """Register event handler"""
        self.event_handlers.append(handler)
    
    async def execute_command(self, command: str, cwd: Optional[str] = None, 
                             env: Optional[Dict[str, str]] = None, 
                             user: Optional[str] = None) -> subprocess.Popen:
        """Execute command with security monitoring"""
        if not self.enabled:
            return subprocess.Popen(command, shell=True, cwd=cwd, env=env)
        
        # Parse command
        parts = command.split()
        executable = parts[0] if parts else command
        arguments = parts[1:] if len(parts) > 1 else []
        
        # Analyze command before execution
        risk_level, violation_type, description = self.pattern_detector.analyze_command(
            command, executable, arguments
        )
        
        # Create process event
        event = ProcessEvent(
            pid=0,  # Will be set after process starts
            command=command,
            executable=executable,
            arguments=arguments,
            user=user,
            risk_level=risk_level,
            violation_type=violation_type,
            description=description,
            details={
                'cwd': cwd,
                'env_keys': list(env.keys()) if env else [],
                'execution_method': 'subprocess'
            }
        )
        
        # Update statistics
        self.guard_stats["executions_monitored"] += 1
        
        # Log execution
        self.logger.info(
            "Command execution monitored",
            command=command,
            risk_level=risk_level.value,
            violation_type=violation_type.value if violation_type else None
        )
        
        # Execute command (DEFENSIVE ONLY - we monitor, don't block)
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Update event with actual PID
            event.pid = process.pid
            event.metadata['start_time'] = datetime.utcnow()
            
            # Store in execution history
            command_hash = hashlib.sha256(command.encode()).hexdigest()
            self.execution_history[command_hash].append(event)
            
            # Notify event handlers
            for handler in self.event_handlers:
                try:
                    handler(event)
                except Exception as e:
                    self.logger.error("Event handler error", handler=str(handler), error=str(e))
            
            # Log high-risk executions
            if risk_level in [ProcessRiskLevel.HIGH, ProcessRiskLevel.CRITICAL]:
                self.guard_stats["alerts_generated"] += 1
                self.logger.warning(
                    "High-risk command executed - DEFENSIVE MONITORING ONLY",
                    pid=process.pid,
                    command=command,
                    risk_level=risk_level.value,
                    description=description
                )
            
            return process
            
        except Exception as e:
            self.logger.error("Command execution failed", command=command, error=str(e))
            raise
    
    async def execute_async_command(self, command: str, cwd: Optional[str] = None,
                                   env: Optional[Dict[str, str]] = None,
                                   user: Optional[str] = None) -> asyncio.subprocess.Process:
        """Execute command asynchronously with security monitoring"""
        if not self.enabled:
            return await asyncio.create_subprocess_shell(command, cwd=cwd, env=env)
        
        # Parse command
        parts = command.split()
        executable = parts[0] if parts else command
        arguments = parts[1:] if len(parts) > 1 else []
        
        # Analyze command before execution
        risk_level, violation_type, description = self.pattern_detector.analyze_command(
            command, executable, arguments
        )
        
        # Create process event
        event = ProcessEvent(
            pid=0,  # Will be set after process starts
            command=command,
            executable=executable,
            arguments=arguments,
            user=user,
            risk_level=risk_level,
            violation_type=violation_type,
            description=description,
            details={
                'cwd': cwd,
                'env_keys': list(env.keys()) if env else [],
                'execution_method': 'async_subprocess'
            }
        )
        
        # Update statistics
        self.guard_stats["executions_monitored"] += 1
        
        # Log execution
        self.logger.info(
            "Async command execution monitored",
            command=command,
            risk_level=risk_level.value,
            violation_type=violation_type.value if violation_type else None
        )
        
        # Execute command (DEFENSIVE ONLY - we monitor, don't block)
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Update event with actual PID
            event.pid = process.pid
            event.metadata['start_time'] = datetime.utcnow()
            
            # Store in execution history
            command_hash = hashlib.sha256(command.encode()).hexdigest()
            self.execution_history[command_hash].append(event)
            
            # Notify event handlers
            for handler in self.event_handlers:
                try:
                    handler(event)
                except Exception as e:
                    self.logger.error("Event handler error", handler=str(handler), error=str(e))
            
            # Log high-risk executions
            if risk_level in [ProcessRiskLevel.HIGH, ProcessRiskLevel.CRITICAL]:
                self.guard_stats["alerts_generated"] += 1
                self.logger.warning(
                    "High-risk async command executed - DEFENSIVE MONITORING ONLY",
                    pid=process.pid,
                    command=command,
                    risk_level=risk_level.value,
                    description=description
                )
            
            return process
            
        except Exception as e:
            self.logger.error("Async command execution failed", command=command, error=str(e))
            raise
    
    def get_execution_history(self, command_hash: Optional[str] = None, limit: int = 100) -> List[ProcessEvent]:
        """Get execution history"""
        if command_hash:
            return self.execution_history.get(command_hash, [])
        
        # Return all events
        all_events = []
        for events in self.execution_history.values():
            all_events.extend(events)
        
        # Sort by timestamp and return most recent
        all_events.sort(key=lambda x: x.timestamp, reverse=True)
        return all_events[:limit]
    
    def get_guard_statistics(self) -> Dict[str, Any]:
        """Get process guard statistics"""
        return {
            "enabled": self.enabled,
            **self.guard_stats,
            "execution_history_size": sum(len(events) for events in self.execution_history.values()),
            "blocked_commands_count": len(self.blocked_commands),
            "process_monitor_stats": self.process_monitor.get_monitoring_statistics()
        }


# Global process guard instance
process_guard = ProcessGuard()


async def start_process_guard():
    """Start process guard"""
    await process_guard.start()


async def stop_process_guard():
    """Stop process guard"""
    await process_guard.stop()


def execute_command_with_guard(command: str, **kwargs) -> subprocess.Popen:
    """Execute command with process guard monitoring"""
    return asyncio.run(process_guard.execute_command(command, **kwargs))


async def execute_async_command_with_guard(command: str, **kwargs) -> asyncio.subprocess.Process:
    """Execute async command with process guard monitoring"""
    return await process_guard.execute_async_command(command, **kwargs)


def get_process_guard_statistics() -> Dict[str, Any]:
    """Get process guard statistics"""
    return process_guard.get_guard_statistics()
