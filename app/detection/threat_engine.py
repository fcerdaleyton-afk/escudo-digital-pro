"""
Threat Detection Engine for Mary V5 Enterprise
Advanced ransomware, malware, and suspicious process detection
"""

import os
import time
import json
import hashlib
import asyncio
import psutil
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum

from app.core.dependencies import logger
from app.core.centralized_logging import log_security_event, log_audit_event


class ThreatType(Enum):
    """Threat classification types"""
    RANSOMWARE = "ransomware"
    MALWARE = "malware"
    SUSPICIOUS_PROCESS = "suspicious_process"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_INJECTION = "command_injection"
    FILE_ENCRYPTION = "file_encryption"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatEvent:
    """Threat event data structure"""
    id: str
    type: ThreatType
    severity: ThreatSeverity
    timestamp: datetime
    source: str
    description: str
    evidence: Dict[str, Any]
    confidence: float
    process_info: Optional[Dict[str, Any]] = None
    file_info: Optional[Dict[str, Any]] = None
    network_info: Optional[Dict[str, Any]] = None


class RansomwareDetector:
    """Ransomware behavior detection"""
    
    def __init__(self):
        self.enabled = os.getenv("RANSOMWARE_DETECTION_ENABLED", "true").lower() == "true"
        
        # Ransomware indicators
        self.file_encryption_extensions = {
            ".locked", ".encrypted", ".crypted", ".crypto", ".locked",
            ".README", ".DECRYPT", ".decrypt_files", ".recover_files"
        }
        
        self.ransomware_processes = {
            "wannacry", "petya", "notpetya", "badrabbit", "wannacry",
            "cryptolocker", "locky", "cerber", "ryuk", "maze", "sodinokibi"
        }
        
        self.ransomware_patterns = [
            r".*\.locked$", r".*\.encrypted$", r".*\.crypted$",
            r".*README\.txt$", r".*DECRYPT.*\.txt$", r".*recover_files.*"
        ]
        
        # File modification tracking
        self.file_modifications = defaultdict(lambda: deque(maxlen=100))
        self.encryption_threshold = int(os.getenv("ENCRYPTION_THRESHOLD", "50"))
        
        logger.info("Ransomware detector initialized", enabled=self.enabled)
    
    async def detect_ransomware_activity(self) -> List[ThreatEvent]:
        """Detect ransomware-like activity"""
        if not self.enabled:
            return []
        
        threats = []
        current_time = datetime.utcnow()
        
        # Monitor file system changes
        file_threats = await self._monitor_file_changes()
        threats.extend(file_threats)
        
        # Monitor suspicious processes
        process_threats = await self._monitor_ransomware_processes()
        threats.extend(process_threats)
        
        # Check for ransomware notes
        note_threats = await self._check_ransomware_notes()
        threats.extend(note_threats)
        
        return threats
    
    async def _monitor_file_changes(self) -> List[ThreatEvent]:
        """Monitor for suspicious file changes"""
        threats = []
        
        try:
            # Get recent file modifications
            recent_files = self._get_recent_file_modifications()
            
            # Check for encryption patterns
            encrypted_files = []
            for file_path, modification_time in recent_files:
                if self._is_encrypted_file(file_path):
                    encrypted_files.append(file_path)
            
            # Detect mass encryption
            if len(encrypted_files) >= self.encryption_threshold:
                threat = ThreatEvent(
                    id=f"ransomware_{int(time.time())}",
                    type=ThreatType.RANSOMWARE,
                    severity=ThreatSeverity.CRITICAL,
                    timestamp=datetime.utcnow(),
                    source="file_system",
                    description=f"Mass file encryption detected: {len(encrypted_files)} files",
                    evidence={
                        "encrypted_files": encrypted_files[:10],  # Limit for logging
                        "total_encrypted": len(encrypted_files),
                        "threshold": self.encryption_threshold
                    },
                    confidence=0.9
                )
                threats.append(threat)
                
                await self._log_threat_event(threat)
        
        except Exception as e:
            logger.error("File monitoring error", error=str(e))
        
        return threats
    
    def _get_recent_file_modifications(self) -> List[Tuple[str, float]]:
        """Get recently modified files"""
        recent_files = []
        current_time = time.time()
        time_window = 300  # 5 minutes
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if proc.info['open_files']:
                        for file_info in proc.info['open_files']:
                            file_path = file_info.path
                            mod_time = os.path.getmtime(file_path)
                            
                            if current_time - mod_time <= time_window:
                                recent_files.append((file_path, mod_time))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.error("Error getting file modifications", error=str(e))
        
        return recent_files
    
    def _is_encrypted_file(self, file_path: str) -> bool:
        """Check if file appears to be encrypted"""
        file_name = os.path.basename(file_path).lower()
        
        # Check extension
        for ext in self.file_encryption_extensions:
            if file_name.endswith(ext):
                return True
        
        # Check patterns
        for pattern in self.ransomware_patterns:
            if re.match(pattern, file_name, re.IGNORECASE):
                return True
        
        return False
    
    async def _monitor_ransomware_processes(self) -> List[ThreatEvent]:
        """Monitor for ransomware processes"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    process_name = proc.info['name'].lower() if proc.info['name'] else ""
                    cmdline = " ".join(proc.info['cmdline'] or []).lower()
                    
                    # Check for ransomware process names
                    if any(ransom_name in process_name for ransom_name in self.ransomware_processes):
                        threat = ThreatEvent(
                            id=f"ransomware_proc_{proc.info['pid']}_{int(time.time())}",
                            type=ThreatType.RANSOMWARE,
                            severity=ThreatSeverity.CRITICAL,
                            timestamp=datetime.utcnow(),
                            source="process_monitor",
                            description=f"Ransomware process detected: {process_name}",
                            evidence={
                                "process_name": process_name,
                                "pid": proc.info['pid'],
                                "cmdline": proc.info['cmdline']
                            },
                            confidence=0.95,
                            process_info={
                                "pid": proc.info['pid'],
                                "name": proc.info['name'],
                                "cmdline": proc.info['cmdline']
                            }
                        )
                        threats.append(threat)
                        await self._log_threat_event(threat)
                    
                    # Check for suspicious command line arguments
                    suspicious_args = [
                        "-encrypt", "-lock", "-crypt", "-decrypt",
                        "--encrypt", "--lock", "--crypt", "--decrypt"
                    ]
                    
                    if any(arg in cmdline for arg in suspicious_args):
                        threat = ThreatEvent(
                            id=f"suspicious_proc_{proc.info['pid']}_{int(time.time())}",
                            type=ThreatType.SUSPICIOUS_PROCESS,
                            severity=ThreatSeverity.HIGH,
                            timestamp=datetime.utcnow(),
                            source="process_monitor",
                            description=f"Suspicious encryption arguments detected: {process_name}",
                            evidence={
                                "process_name": process_name,
                                "pid": proc.info['pid'],
                                "cmdline": proc.info['cmdline'],
                                "suspicious_args": [arg for arg in suspicious_args if arg in cmdline]
                            },
                            confidence=0.8,
                            process_info=proc.info
                        )
                        threats.append(threat)
                        await self._log_threat_event(threat)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error("Process monitoring error", error=str(e))
        
        return threats
    
    async def _check_ransomware_notes(self) -> List[ThreatEvent]:
        """Check for ransomware notes"""
        threats = []
        
        try:
            # Common ransomware note patterns
            note_patterns = [
                r".*README.*\.txt$", r".*DECRYPT.*\.txt$", r".*recover.*\.txt$",
                r".*YOUR.*FILES.*\.txt$", r".*HOW.*TO.*DECRYPT.*\.txt$"
            ]
            
            # Search for ransomware notes in common directories
            search_dirs = [
                os.path.expanduser("~"),  # User home
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents")
            ]
            
            for search_dir in search_dirs:
                if os.path.exists(search_dir):
                    for root, dirs, files in os.walk(search_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Check if file matches ransomware note patterns
                            for pattern in note_patterns:
                                if re.match(pattern, file, re.IGNORECASE):
                                    # Check file content for ransomware indicators
                                    if self._is_ransomware_note(file_path):
                                        threat = ThreatEvent(
                                            id=f"ransomware_note_{int(time.time())}",
                                            type=ThreatType.RANSOMWARE,
                                            severity=ThreatSeverity.HIGH,
                                            timestamp=datetime.utcnow(),
                                            source="file_system",
                                            description=f"Ransomware note detected: {file_path}",
                                            evidence={
                                                "note_path": file_path,
                                                "file_name": file
                                            },
                                            confidence=0.85,
                                            file_info={
                                                "path": file_path,
                                                "name": file
                                            }
                                        )
                                        threats.append(threat)
                                        await self._log_threat_event(threat)
        
        except Exception as e:
            logger.error("Ransomware note check error", error=str(e))
        
        return threats
    
    def _is_ransomware_note(self, file_path: str) -> bool:
        """Check if file is a ransomware note"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
                
            # Ransomware note keywords
            note_keywords = [
                "bitcoin", "cryptocurrency", "pay", "ransom", "decrypt",
                "files encrypted", "restore", "recover", "payment",
                "wallet", "private key", "instructions"
            ]
            
            keyword_count = sum(1 for keyword in note_keywords if keyword in content)
            
            # Consider it a ransomware note if multiple keywords are present
            return keyword_count >= 3
        
        except Exception:
            return False
    
    async def _log_threat_event(self, threat: ThreatEvent):
        """Log ransomware threat event"""
        log_security_event(
            "ransomware_detected",
            {
                "threat_id": threat.id,
                "type": threat.type.value,
                "severity": threat.severity.value,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


class MalwareDetector:
    """Malware detection engine"""
    
    def __init__(self):
        self.enabled = os.getenv("MALWARE_DETECTION_ENABLED", "true").lower() == "true"
        
        # Malware indicators
        self.suspicious_processes = {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe"
        }
        
        self.malware_patterns = [
            r"powershell.*-enc", r"powershell.*-nop", r"powershell.*-w hidden",
            r"cmd.*\/c", r"rundll32.*javascript", r"wscript.*\/\/e"
        ]
        
        # Process behavior tracking
        self.process_behaviors = defaultdict(list)
        
        logger.info("Malware detector initialized", enabled=self.enabled)
    
    async def detect_malware_activity(self) -> List[ThreatEvent]:
        """Detect malware-like activity"""
        if not self.enabled:
            return []
        
        threats = []
        
        # Monitor suspicious processes
        process_threats = await self._monitor_suspicious_processes()
        threats.extend(process_threats)
        
        # Check for encoded commands
        encoded_threats = await self._detect_encoded_commands()
        threats.extend(encoded_threats)
        
        # Monitor process creation patterns
        creation_threats = await self._monitor_process_creation()
        threats.extend(creation_threats)
        
        return threats
    
    async def _monitor_suspicious_processes(self) -> List[ThreatEvent]:
        """Monitor for suspicious system processes"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    process_name = proc.info['name'].lower() if proc.info['name'] else ""
                    cmdline = " ".join(proc.info['cmdline'] or []).lower()
                    
                    # Check for suspicious processes
                    if process_name in self.suspicious_processes:
                        # Check for suspicious arguments
                        suspicious_patterns = [
                            r"-enc", r"-nop", r"-w hidden", r"\/c", r"\/\/e",
                            r"javascript:", r"vbscript:", r"powershell"
                        ]
                        
                        if any(re.search(pattern, cmdline) for pattern in suspicious_patterns):
                            threat = ThreatEvent(
                                id=f"malware_proc_{proc.info['pid']}_{int(time.time())}",
                                type=ThreatType.MALWARE,
                                severity=ThreatSeverity.HIGH,
                                timestamp=datetime.utcnow(),
                                source="process_monitor",
                                description=f"Suspicious process activity: {process_name}",
                                evidence={
                                    "process_name": process_name,
                                    "pid": proc.info['pid'],
                                    "cmdline": proc.info['cmdline'],
                                    "cpu_percent": proc.info.get('cpu_percent', 0),
                                    "memory_percent": proc.info.get('memory_percent', 0)
                                },
                                confidence=0.8,
                                process_info=proc.info
                            )
                            threats.append(threat)
                            await self._log_threat_event(threat)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error("Suspicious process monitoring error", error=str(e))
        
        return threats
    
    async def _detect_encoded_commands(self) -> List[ThreatEvent]:
        """Detect encoded or obfuscated commands"""
        threats = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = " ".join(proc.info['cmdline'] or [])
                    
                    # Check for Base64 encoded content
                    if self._contains_base64(cmdline):
                        threat = ThreatEvent(
                            id=f"encoded_cmd_{proc.info['pid']}_{int(time.time())}",
                            type=ThreatType.COMMAND_INJECTION,
                            severity=ThreatSeverity.HIGH,
                            timestamp=datetime.utcnow(),
                            source="process_monitor",
                            description=f"Encoded command detected: {proc.info['name']}",
                            evidence={
                                "process_name": proc.info['name'],
                                "pid": proc.info['pid'],
                                "cmdline": proc.info['cmdline']
                            },
                            confidence=0.75,
                            process_info=proc.info
                        )
                        threats.append(threat)
                        await self._log_threat_event(threat)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error("Encoded command detection error", error=str(e))
        
        return threats
    
    def _contains_base64(self, text: str) -> bool:
        """Check if text contains Base64 encoded content"""
        import base64
        import re
        
        # Look for Base64 patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        for match in matches:
            try:
                # Try to decode
                decoded = base64.b64decode(match).decode('utf-8')
                # If it decodes to readable text, it's likely encoded
                if len(decoded) > 10 and all(ord(c) < 128 for c in decoded):
                    return True
            except:
                continue
        
        return False
    
    async def _monitor_process_creation(self) -> List[ThreatEvent]:
        """Monitor for suspicious process creation patterns"""
        threats = []
        
        try:
            # Get process tree
            processes = list(psutil.process_iter(['pid', 'ppid', 'name', 'cmdline']))
            
            # Look for suspicious parent-child relationships
            for proc in processes:
                try:
                    if proc.info['ppid']:
                        parent = psutil.Process(proc.info['ppid'])
                        parent_name = parent.name().lower()
                        child_name = proc.info['name'].lower()
                        
                        # Suspicious parent-child combinations
                        suspicious_combinations = [
                            ("explorer.exe", "powershell.exe"),
                            ("winword.exe", "cmd.exe"),
                            ("excel.exe", "powershell.exe"),
                            ("powershell.exe", "rundll32.exe")
                        ]
                        
                        for parent_proc, child_proc in suspicious_combinations:
                            if parent_proc in parent_name and child_proc in child_name:
                                threat = ThreatEvent(
                                    id=f"suspicious_creation_{proc.info['pid']}_{int(time.time())}",
                                    type=ThreatType.MALWARE,
                                    severity=ThreatSeverity.MEDIUM,
                                    timestamp=datetime.utcnow(),
                                    source="process_monitor",
                                    description=f"Suspicious process creation: {parent_name} -> {child_name}",
                                    evidence={
                                        "parent": parent_name,
                                        "child": child_name,
                                        "parent_pid": proc.info['ppid'],
                                        "child_pid": proc.info['pid']
                                    },
                                    confidence=0.7,
                                    process_info=proc.info
                                )
                                threats.append(threat)
                                await self._log_threat_event(threat)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error("Process creation monitoring error", error=str(e))
        
        return threats
    
    async def _log_threat_event(self, threat: ThreatEvent):
        """Log malware threat event"""
        log_security_event(
            "malware_detected",
            {
                "threat_id": threat.id,
                "type": threat.type.value,
                "severity": threat.severity.value,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
        )


class ThreatDetectionEngine:
    """Main threat detection engine"""
    
    def __init__(self):
        self.enabled = os.getenv("THREAT_DETECTION_ENABLED", "true").lower() == "true"
        
        # Initialize detectors
        self.ransomware_detector = RansomwareDetector()
        self.malware_detector = MalwareDetector()
        
        # Threat history
        self.threat_history = deque(maxlen=1000)
        self.threat_stats = defaultdict(int)
        
        # Detection interval
        self.detection_interval = int(os.getenv("DETECTION_INTERVAL", "30"))  # seconds
        
        logger.info("Threat detection engine initialized", enabled=self.enabled)
    
    async def start_monitoring(self):
        """Start continuous threat monitoring"""
        if not self.enabled:
            return
        
        logger.info("Starting threat monitoring")
        
        while True:
            try:
                # Run all detectors
                all_threats = []
                
                # Ransomware detection
                ransomware_threats = await self.ransomware_detector.detect_ransomware_activity()
                all_threats.extend(ransomware_threats)
                
                # Malware detection
                malware_threats = await self.malware_detector.detect_malware_activity()
                all_threats.extend(malware_threats)
                
                # Process threats
                for threat in all_threats:
                    self.threat_history.append(threat)
                    self.threat_stats[threat.type.value] += 1
                
                # Log summary
                if all_threats:
                    logger.info(
                        "Threat detection cycle completed",
                        threats_detected=len(all_threats),
                        threat_types=[t.type.value for t in all_threats]
                    )
                
                # Wait for next cycle
                await asyncio.sleep(self.detection_interval)
                
            except Exception as e:
                logger.error("Threat monitoring error", error=str(e))
                await asyncio.sleep(self.detection_interval)
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get threat detection summary"""
        recent_threats = list(self.threat_history)[-100:]  # Last 100 threats
        
        return {
            "total_threats": len(self.threat_history),
            "recent_threats": len(recent_threats),
            "threat_types": dict(self.threat_stats),
            "last_detection": recent_threats[-1].timestamp.isoformat() if recent_threats else None,
            "enabled": self.enabled,
            "detection_interval": self.detection_interval
        }
    
    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent threats"""
        recent_threats = list(self.threat_history)[-limit:]
        
        return [
            {
                "id": threat.id,
                "type": threat.type.value,
                "severity": threat.severity.value,
                "timestamp": threat.timestamp.isoformat(),
                "source": threat.source,
                "description": threat.description,
                "confidence": threat.confidence,
                "evidence": threat.evidence
            }
            for threat in recent_threats
        ]


# Global threat detection engine
threat_detection_engine = ThreatDetectionEngine()


def get_threat_detection_engine() -> ThreatDetectionEngine:
    """Get global threat detection engine"""
    return threat_detection_engine


async def start_threat_monitoring():
    """Start threat monitoring"""
    await threat_detection_engine.start_monitoring()


def get_threat_summary() -> Dict[str, Any]:
    """Get threat detection summary"""
    return threat_detection_engine.get_threat_summary()


def get_recent_threats(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent threats"""
    return threat_detection_engine.get_recent_threats(limit)
