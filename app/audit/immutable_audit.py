#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Immutable Audit Strategy
Comprehensive immutable logging with tamper detection and secure archival
"""

import os
import sys
import asyncio
import logging
import json
import time
import hashlib
import hmac
import cryptography
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import weakref
import sqlite3
import gzip
import shutil
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/immutable_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Audit event type enumeration"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_ACTION = "user_action"
    SYSTEM_EVENT = "system_event"
    SECURITY_EVENT = "security_event"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIG_CHANGE = "config_change"
    ERROR_EVENT = "error_event"
    COMPLIANCE_EVENT = "compliance_event"


class AuditSeverity(Enum):
    """Audit severity enumeration"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RetentionPolicy(Enum):
    """Retention policy enumeration"""
    IMMEDIATE = "immediate"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"
    PERMANENT = "permanent"


@dataclass
class AuditEvent:
    """Audit event data structure"""
    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: datetime
    user_id: Optional[str]
    session_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    resource: Optional[str]
    action: Optional[str]
    details: Dict[str, Any]
    metadata: Dict[str, Any]
    integrity_hash: str
    previous_hash: str
    sequence_number: int
    signature: Optional[str] = None


@dataclass
class RetentionPolicyConfig:
    """Retention policy configuration"""
    policy_name: str
    event_types: List[AuditEventType]
    retention_period: timedelta
    archival_after: timedelta
    encryption_required: bool = True
    compression_enabled: bool = True
    backup_required: bool = True
    compliance_flags: List[str] = field(default_factory=list)


@dataclass
class AuditChain:
    """Audit chain for integrity verification"""
    chain_id: str
    start_hash: str
    current_hash: str
    sequence_number: int
    created_at: datetime
    last_updated: datetime
    events_count: int
    is_valid: bool


class AppendOnlyLogManager:
    """Append-only log manager with write-once semantics"""
    
    def __init__(self, log_directory: str = "/app/audit/logs"):
        """Initialize append-only log manager"""
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        self.current_log_file = None
        self.current_log_path = None
        self.sequence_number = 0
        self.file_size_limit = 100 * 1024 * 1024  # 100MB
        self.max_files_per_day = 100
        
        # Chain management
        self.chains: Dict[str, AuditChain] = {}
        self.current_chain_id = None
        
        # Write protection
        self.write_protection_enabled = True
        self.hash_verification_enabled = True
        
        logger.info("Append-only log manager initialized")
    
    async def initialize(self):
        """Initialize log manager"""
        try:
            # Load existing chains
            await self._load_chains()
            
            # Create new day's log file
            await self._create_new_log_file()
            
            logger.info("Append-only log manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing log manager: {e}")
            raise
    
    async def _load_chains(self):
        """Load existing audit chains"""
        try:
            chains_file = self.log_directory / "chains.json"
            
            if chains_file.exists():
                with open(chains_file, 'r') as f:
                    chains_data = json.load(f)
                
                for chain_id, chain_data in chains_data.items():
                    self.chains[chain_id] = AuditChain(
                        chain_id=chain_id,
                        start_hash=chain_data['start_hash'],
                        current_hash=chain_data['current_hash'],
                        sequence_number=chain_data['sequence_number'],
                        created_at=datetime.fromisoformat(chain_data['created_at']),
                        last_updated=datetime.fromisoformat(chain_data['last_updated']),
                        events_count=chain_data['events_count'],
                        is_valid=chain_data['is_valid']
                    )
            
            # Create new chain if needed
            if not self.chains:
                await self._create_new_chain()
            else:
                # Use the most recent chain
                self.current_chain_id = max(self.chains.keys(), 
                                        key=lambda k: self.chains[k].last_updated)
                self.sequence_number = self.chains[self.current_chain_id].sequence_number
            
        except Exception as e:
            logger.error(f"Error loading chains: {e}")
            raise
    
    async def _create_new_chain(self):
        """Create new audit chain"""
        try:
            chain_id = f"chain_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            start_hash = hashlib.sha256(chain_id.encode()).hexdigest()
            
            chain = AuditChain(
                chain_id=chain_id,
                start_hash=start_hash,
                current_hash=start_hash,
                sequence_number=0,
                created_at=datetime.utcnow(),
                last_updated=datetime.utcnow(),
                events_count=0,
                is_valid=True
            )
            
            self.chains[chain_id] = chain
            self.current_chain_id = chain_id
            self.sequence_number = 0
            
            await self._save_chains()
            
            logger.info(f"Created new audit chain: {chain_id}")
            
        except Exception as e:
            logger.error(f"Error creating new chain: {e}")
            raise
    
    async def _create_new_log_file(self):
        """Create new log file"""
        try:
            date_str = datetime.utcnow().strftime("%Y-%m-%d")
            timestamp_str = datetime.utcnow().strftime("%H%M%S")
            
            log_filename = f"audit_{date_str}_{timestamp_str}.log"
            self.current_log_path = self.log_directory / log_filename
            
            # Create file with write protection
            self.current_log_file = open(self.current_log_path, 'ab')
            
            # Write file header with chain information
            header = {
                'file_type': 'immutable_audit_log',
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat(),
                'chain_id': self.current_chain_id,
                'start_sequence': self.sequence_number
            }
            
            header_bytes = json.dumps(header).encode('utf-8')
            self.current_log_file.write(header_bytes)
            self.current_log_file.write(b'\n---\n')
            self.current_log_file.flush()
            
            logger.info(f"Created new log file: {log_filename}")
            
        except Exception as e:
            logger.error(f"Error creating new log file: {e}")
            raise
    
    async def write_event(self, event: AuditEvent) -> bool:
        """Write audit event to append-only log"""
        try:
            if not self.current_log_file:
                await self._create_new_log_file()
            
            # Check file size limit
            if self._get_file_size() > self.file_size_limit:
                await self._rotate_log_file()
            
            # Verify write protection
            if self.write_protection_enabled:
                await self._verify_write_protection()
            
            # Calculate integrity hash
            event.integrity_hash = await self._calculate_event_hash(event)
            
            # Set previous hash
            if self.current_chain_id in self.chains:
                event.previous_hash = self.chains[self.current_chain_id].current_hash
            
            # Set sequence number
            event.sequence_number = self.sequence_number
            self.sequence_number += 1
            
            # Serialize event
            event_data = {
                'event_id': event.event_id,
                'event_type': event.event_type.value,
                'severity': event.severity.value,
                'timestamp': event.timestamp.isoformat(),
                'user_id': event.user_id,
                'session_id': event.session_id,
                'ip_address': event.ip_address,
                'user_agent': event.user_agent,
                'resource': event.resource,
                'action': event.action,
                'details': event.details,
                'metadata': event.metadata,
                'integrity_hash': event.integrity_hash,
                'previous_hash': event.previous_hash,
                'sequence_number': event.sequence_number,
                'signature': event.signature
            }
            
            # Write to file
            event_bytes = json.dumps(event_data).encode('utf-8')
            self.current_log_file.write(event_bytes)
            self.current_log_file.write(b'\n')
            self.current_log_file.flush()
            
            # Update chain
            await self._update_chain(event)
            
            logger.debug(f"Event written to log: {event.event_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error writing event to log: {e}")
            return False
    
    async def _calculate_event_hash(self, event: AuditEvent) -> str:
        """Calculate event integrity hash"""
        try:
            # Create hash data
            hash_data = {
                'event_id': event.event_id,
                'event_type': event.event_type.value,
                'timestamp': event.timestamp.isoformat(),
                'user_id': event.user_id,
                'resource': event.resource,
                'action': event.action,
                'details': sorted(event.details.items())
            }
            
            # Calculate SHA-256 hash
            hash_string = json.dumps(hash_data, sort_keys=True)
            return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating event hash: {e}")
            return ""
    
    async def _update_chain(self, event: AuditEvent):
        """Update audit chain with new event"""
        try:
            if self.current_chain_id not in self.chains:
                return
            
            chain = self.chains[self.current_chain_id]
            chain.current_hash = event.integrity_hash
            chain.sequence_number = event.sequence_number
            chain.last_updated = datetime.utcnow()
            chain.events_count += 1
            
            # Verify chain integrity periodically
            if chain.events_count % 100 == 0:
                await self._verify_chain_integrity(chain.chain_id)
            
            await self._save_chains()
            
        except Exception as e:
            logger.error(f"Error updating chain: {e}")
    
    async def _verify_chain_integrity(self, chain_id: str) -> bool:
        """Verify chain integrity"""
        try:
            if chain_id not in self.chains:
                return False
            
            chain = self.chains[chain_id]
            
            # Read all events in chain
            events = await self._read_chain_events(chain_id)
            
            if not events:
                return True
            
            # Verify hash chain
            previous_hash = chain.start_hash
            for event in events:
                if event.previous_hash != previous_hash:
                    logger.error(f"Chain integrity broken at event {event.sequence_number}")
                    chain.is_valid = False
                    return False
                
                # Verify event hash
                calculated_hash = await self._calculate_event_hash(event)
                if calculated_hash != event.integrity_hash:
                    logger.error(f"Event hash mismatch for event {event.event_id}")
                    chain.is_valid = False
                    return False
                
                previous_hash = event.integrity_hash
            
            chain.is_valid = True
            return True
            
        except Exception as e:
            logger.error(f"Error verifying chain integrity: {e}")
            return False
    
    async def _read_chain_events(self, chain_id: str) -> List[AuditEvent]:
        """Read all events in a chain"""
        try:
            events = []
            
            # Find all log files for this chain
            log_files = list(self.log_directory.glob("*.log"))
            
            for log_file in log_files:
                async with aiofiles.open(log_file, 'rb') as f:
                    content = await f.read()
                    
                    # Skip header
                    header_end = content.find(b'---\n')
                    if header_end == -1:
                        continue
                    
                    content = content[header_end + 4:]
                    
                    # Parse events
                    for line in content.split(b'\n'):
                        if line.strip():
                            try:
                                event_data = json.loads(line.decode('utf-8'))
                                
                                # Check if event belongs to this chain
                                if event_data.get('previous_hash') == chain.start_hash or \
                                   event_data.get('previous_hash') in [e.integrity_hash for e in events]:
                                    
                                    event = AuditEvent(
                                        event_id=event_data['event_id'],
                                        event_type=AuditEventType(event_data['event_type']),
                                        severity=AuditSeverity(event_data['severity']),
                                        timestamp=datetime.fromisoformat(event_data['timestamp']),
                                        user_id=event_data.get('user_id'),
                                        session_id=event_data.get('session_id'),
                                        ip_address=event_data.get('ip_address'),
                                        user_agent=event_data.get('user_agent'),
                                        resource=event_data.get('resource'),
                                        action=event_data.get('action'),
                                        details=event_data.get('details', {}),
                                        metadata=event_data.get('metadata', {}),
                                        integrity_hash=event_data['integrity_hash'],
                                        previous_hash=event_data['previous_hash'],
                                        sequence_number=event_data['sequence_number'],
                                        signature=event_data.get('signature')
                                    )
                                    
                                    events.append(event)
                                    
                            except json.JSONDecodeError:
                                continue
            
            return sorted(events, key=lambda x: x.sequence_number)
            
        except Exception as e:
            logger.error(f"Error reading chain events: {e}")
            return []
    
    async def _verify_write_protection(self):
        """Verify write protection"""
        try:
            if not self.current_log_path:
                return
            
            # Check if file is append-only
            stat = os.stat(self.current_log_path)
            
            # In a real implementation, this would check file permissions
            # and verify that the file hasn't been modified
            
            return True
            
        except Exception as e:
            logger.error(f"Error verifying write protection: {e}")
            return False
    
    async def _rotate_log_file(self):
        """Rotate log file"""
        try:
            # Close current file
            if self.current_log_file:
                self.current_log_file.close()
            
            # Create new file
            await self._create_new_log_file()
            
            logger.info("Log file rotated")
            
        except Exception as e:
            logger.error(f"Error rotating log file: {e}")
    
    def _get_file_size(self) -> int:
        """Get current log file size"""
        try:
            if self.current_log_path and self.current_log_path.exists():
                return self.current_log_path.stat().st_size
            return 0
        except Exception:
            return 0
    
    async def _save_chains(self):
        """Save chains to file"""
        try:
            chains_file = self.log_directory / "chains.json"
            
            chains_data = {}
            for chain_id, chain in self.chains.items():
                chains_data[chain_id] = {
                    'start_hash': chain.start_hash,
                    'current_hash': chain.current_hash,
                    'sequence_number': chain.sequence_number,
                    'created_at': chain.created_at.isoformat(),
                    'last_updated': chain.last_updated.isoformat(),
                    'events_count': chain.events_count,
                    'is_valid': chain.is_valid
                }
            
            with open(chains_file, 'w') as f:
                json.dump(chains_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving chains: {e}")


class TamperDetectionSystem:
    """Tamper detection and integrity verification system"""
    
    def __init__(self):
        """Initialize tamper detection system"""
        self.master_key = None
        self.hmac_keys = {}
        self.detection_enabled = True
        self.verification_interval = 300  # 5 minutes
        self.alert_threshold = 3  # Alert after 3 violations
        
        # Detection statistics
        self.violation_count = 0
        self.last_verification = datetime.utcnow()
        self.verification_history = []
        
        logger.info("Tamper detection system initialized")
    
    async def initialize(self):
        """Initialize tamper detection system"""
        try:
            # Generate master key
            await self._generate_master_key()
            
            # Start verification loop
            asyncio.create_task(self._verification_loop())
            
            logger.info("Tamper detection system initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing tamper detection: {e}")
            raise
    
    async def _generate_master_key(self):
        """Generate master key for HMAC"""
        try:
            # Generate 256-bit master key
            self.master_key = os.urandom(32)
            
            # Generate HMAC keys for different event types
            for event_type in AuditEventType:
                key_material = self.master_key + event_type.value.encode()
                self.hmac_keys[event_type] = hashlib.sha256(key_material).digest()
            
            logger.info("Master key and HMAC keys generated")
            
        except Exception as e:
            logger.error(f"Error generating master key: {e}")
            raise
    
    async def verify_event_integrity(self, event: AuditEvent) -> bool:
        """Verify event integrity"""
        try:
            if not self.detection_enabled:
                return True
            
            # Get HMAC key for event type
            hmac_key = self.hmac_keys.get(event.event_type)
            if not hmac_key:
                logger.error(f"No HMAC key for event type: {event.event_type}")
                return False
            
            # Calculate expected HMAC
            event_data = {
                'event_id': event.event_id,
                'event_type': event.event_type.value,
                'timestamp': event.timestamp.isoformat(),
                'user_id': event.user_id,
                'resource': event.resource,
                'action': event.action,
                'details': sorted(event.details.items())
            }
            
            message = json.dumps(event_data, sort_keys=True).encode('utf-8')
            expected_hmac = hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
            
            # Compare with stored signature
            if event.signature and event.signature != expected_hmac:
                await self._handle_tampering("signature_mismatch", event)
                return False
            
            # Verify integrity hash
            calculated_hash = hashlib.sha256(message).hexdigest()
            if calculated_hash != event.integrity_hash:
                await self._handle_tampering("hash_mismatch", event)
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error verifying event integrity: {e}")
            return False
    
    async def verify_chain_integrity(self, chain_id: str, events: List[AuditEvent]) -> bool:
        """Verify chain integrity"""
        try:
            if not events:
                return True
            
            violations = []
            
            # Verify hash chain
            previous_hash = events[0].previous_hash
            for i, event in enumerate(events):
                # Verify hash chain
                if event.previous_hash != previous_hash:
                    violations.append({
                        'type': 'hash_chain_break',
                        'event_id': event.event_id,
                        'sequence_number': event.sequence_number,
                        'expected_previous': previous_hash,
                        'actual_previous': event.previous_hash
                    })
                
                # Verify event integrity
                if not await self.verify_event_integrity(event):
                    violations.append({
                        'type': 'event_integrity',
                        'event_id': event.event_id,
                        'sequence_number': event.sequence_number
                    })
                
                previous_hash = event.integrity_hash
            
            # Handle violations
            if violations:
                await self._handle_chain_tampering(chain_id, violations)
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error verifying chain integrity: {e}")
            return False
    
    async def _handle_tampering(self, tamper_type: str, event: AuditEvent):
        """Handle tampering detection"""
        try:
            self.violation_count += 1
            
            # Create tampering event
            tampering_event = {
                'tamper_type': tamper_type,
                'detected_at': datetime.utcnow().isoformat(),
                'event_id': event.event_id,
                'sequence_number': event.sequence_number,
                'user_id': event.user_id,
                'severity': 'critical'
            }
            
            self.verification_history.append(tampering_event)
            
            # Log tampering
            logger.critical(f"Tampering detected: {tamper_type} for event {event.event_id}")
            
            # Alert if threshold exceeded
            if self.violation_count >= self.alert_threshold:
                await self._send_tampering_alert(tampering_event)
            
        except Exception as e:
            logger.error(f"Error handling tampering: {e}")
    
    async def _handle_chain_tampering(self, chain_id: str, violations: List[Dict[str, Any]]):
        """Handle chain tampering detection"""
        try:
            self.violation_count += len(violations)
            
            # Create tampering event
            tampering_event = {
                'tamper_type': 'chain_tampering',
                'detected_at': datetime.utcnow().isoformat(),
                'chain_id': chain_id,
                'violations': violations,
                'severity': 'critical'
            }
            
            self.verification_history.append(tampering_event)
            
            # Log tampering
            logger.critical(f"Chain tampering detected: {chain_id} with {len(violations)} violations")
            
            # Send alert
            await self._send_tampering_alert(tampering_event)
            
        except Exception as e:
            logger.error(f"Error handling chain tampering: {e}")
    
    async def _send_tampering_alert(self, tampering_event: Dict[str, Any]):
        """Send tampering alert"""
        try:
            # In a real implementation, this would send alerts to monitoring systems
            logger.critical(f"TAMPERING ALERT: {json.dumps(tampering_event, indent=2)}")
            
            # Could integrate with alerting systems, SIEM, etc.
            
        except Exception as e:
            logger.error(f"Error sending tampering alert: {e}")
    
    async def _verification_loop(self):
        """Background verification loop"""
        while True:
            try:
                await asyncio.sleep(self.verification_interval)
                
                if self.detection_enabled:
                    await self._perform_verification()
                    self.last_verification = datetime.utcnow()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in verification loop: {e}")
                await asyncio.sleep(60)
    
    async def _perform_verification(self):
        """Perform periodic verification"""
        try:
            # In a real implementation, this would verify all chains
            # For now, we'll just log the verification
            logger.info("Performing periodic tampering detection verification")
            
        except Exception as e:
            logger.error(f"Error performing verification: {e}")


class SecureArchivalSystem:
    """Secure archival system with encryption and backup"""
    
    def __init__(self, archival_directory: str = "/app/audit/archival"):
        """Initialize secure archival system"""
        self.archival_directory = Path(archival_directory)
        self.archival_directory.mkdir(parents=True, exist_ok=True)
        
        # Encryption keys
        self.encryption_key = None
        self.backup_encryption_key = None
        
        # Archival configuration
        self.compression_enabled = True
        self.encryption_enabled = True
        self.backup_enabled = True
        self.backup_retention = timedelta(days=365)
        
        logger.info("Secure archival system initialized")
    
    async def initialize(self):
        """Initialize archival system"""
        try:
            # Generate encryption keys
            await self._generate_encryption_keys()
            
            logger.info("Secure archival system initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing archival system: {e}")
            raise
    
    async def _generate_encryption_keys(self):
        """Generate encryption keys"""
        try:
            # Generate 256-bit encryption key
            self.encryption_key = os.urandom(32)
            self.backup_encryption_key = os.urandom(32)
            
            logger.info("Encryption keys generated")
            
        except Exception as e:
            logger.error(f"Error generating encryption keys: {e}")
            raise
    
    async def archive_logs(self, log_files: List[Path], retention_policy: RetentionPolicyConfig) -> bool:
        """Archive log files with encryption and compression"""
        try:
            for log_file in log_files:
                await self._archive_single_file(log_file, retention_policy)
            
            return True
            
        except Exception as e:
            logger.error(f"Error archiving logs: {e}")
            return False
    
    async def _archive_single_file(self, log_file: Path, retention_policy: RetentionPolicyConfig):
        """Archive single log file"""
        try:
            # Create archival filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive_filename = f"{log_file.stem}_{timestamp}.archive"
            archive_path = self.archival_directory / archive_filename
            
            # Read log file
            with open(log_file, 'rb') as f:
                log_data = f.read()
            
            # Compress if enabled
            if retention_policy.compression_enabled:
                log_data = gzip.compress(log_data)
                archive_path = archive_path.with_suffix('.archive.gz')
            
            # Encrypt if enabled
            if retention_policy.encryption_enabled:
                log_data = await self._encrypt_data(log_data)
                archive_path = archive_path.with_suffix('.archive.enc')
            
            # Write archived file
            with open(archive_path, 'wb') as f:
                f.write(log_data)
            
            # Create backup if enabled
            if retention_policy.backup_required:
                await self._create_backup(archive_path, retention_policy)
            
            # Create metadata file
            await self._create_archive_metadata(archive_path, log_file, retention_policy)
            
            logger.info(f"Archived log file: {log_file} -> {archive_path}")
            
        except Exception as e:
            logger.error(f"Error archiving file {log_file}: {e}")
            raise
    
    async def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data with AES-256-GCM"""
        try:
            # Generate random IV
            iv = os.urandom(12)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            
            # Encrypt data
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Return IV + ciphertext + tag
            return iv + ciphertext + encryptor.tag
            
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            raise
    
    async def _create_backup(self, archive_path: Path, retention_policy: RetentionPolicyConfig):
        """Create backup of archived file"""
        try:
            backup_directory = self.archival_directory / "backups"
            backup_directory.mkdir(exist_ok=True)
            
            # Create backup filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"{archive_path.name}.backup_{timestamp}"
            backup_path = backup_directory / backup_filename
            
            # Copy file
            shutil.copy2(archive_path, backup_path)
            
            # Encrypt backup if required
            if retention_policy.encryption_required:
                with open(backup_path, 'rb') as f:
                    backup_data = f.read()
                
                encrypted_backup = await self._encrypt_data(backup_data)
                
                with open(backup_path, 'wb') as f:
                    f.write(encrypted_backup)
                
                backup_path = backup_path.with_suffix('.backup.enc')
            
            logger.info(f"Created backup: {backup_path}")
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            raise
    
    async def _create_archive_metadata(self, archive_path: Path, original_file: Path, 
                                    retention_policy: RetentionPolicyConfig):
        """Create archive metadata file"""
        try:
            metadata = {
                'archive_filename': archive_path.name,
                'original_filename': original_file.name,
                'archived_at': datetime.utcnow().isoformat(),
                'retention_policy': retention_policy.policy_name,
                'retention_period': retention_policy.retention_period.total_seconds(),
                'archival_after': retention_policy.archival_after.total_seconds(),
                'encryption_enabled': retention_policy.encryption_enabled,
                'compression_enabled': retention_policy.compression_enabled,
                'backup_required': retention_policy.backup_required,
                'compliance_flags': retention_policy.compliance_flags,
                'file_size': archive_path.stat().st_size,
                'original_size': original_file.stat().st_size if original_file.exists() else 0
            }
            
            metadata_path = archive_path.with_suffix('.meta.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating archive metadata: {e}"


class RetentionPolicyManager:
    """Retention policy management system"""
    
    def __init__(self):
        """Initialize retention policy manager"""
        self.policies: Dict[str, RetentionPolicyConfig] = {}
        self.cleanup_interval = 3600  # 1 hour
        self.cleanup_task: Optional[asyncio.Task] = None
        
        # Default policies
        self._create_default_policies()
        
        logger.info("Retention policy manager initialized")
    
    def _create_default_policies(self):
        """Create default retention policies"""
        try:
            # Security events - 7 years
            self.policies['security'] = RetentionPolicyConfig(
                policy_name='security',
                event_types=[AuditEventType.SECURITY_EVENT, AuditEventType.USER_LOGIN, AuditEventType.USER_LOGOUT],
                retention_period=timedelta(days=7*365),
                archival_after=timedelta(days=30),
                encryption_required=True,
                compression_enabled=True,
                backup_required=True,
                compliance_flags=['SOX', 'HIPAA', 'PCI_DSS', 'GDPR']
            )
            
            # User actions - 3 years
            self.policies['user_actions'] = RetentionPolicyConfig(
                policy_name='user_actions',
                event_types=[AuditEventType.USER_ACTION, AuditEventType.DATA_ACCESS, AuditEventType.DATA_MODIFICATION],
                retention_period=timedelta(days=3*365),
                archival_after=timedelta(days=7),
                encryption_required=True,
                compression_enabled=True,
                backup_required=True,
                compliance_flags=['SOX', 'HIPAA', 'GDPR']
            )
            
            # System events - 1 year
            self.policies['system'] = RetentionPolicyConfig(
                policy_name='system',
                event_types=[AuditEventType.SYSTEM_EVENT, AuditEventType.ERROR_EVENT],
                retention_period=timedelta(days=365),
                archival_after=timedelta(days=1),
                encryption_required=False,
                compression_enabled=True,
                backup_required=True,
                compliance_flags=[]
            )
            
            # Config changes - 5 years
            self.policies['config'] = RetentionPolicyConfig(
                policy_name='config',
                event_types=[AuditEventType.CONFIG_CHANGE],
                retention_period=timedelta(days=5*365),
                archival_after=timedelta(days=7),
                encryption_required=True,
                compression_enabled=True,
                backup_required=True,
                compliance_flags=['SOX', 'PCI_DSS']
            )
            
            # Compliance events - 10 years
            self.policies['compliance'] = RetentionPolicyConfig(
                policy_name='compliance',
                event_types=[AuditEventType.COMPLIANCE_EVENT],
                retention_period=timedelta(days=10*365),
                archival_after=timedelta(days=30),
                encryption_required=True,
                compression_enabled=True,
                backup_required=True,
                compliance_flags=['SOX', 'HIPAA', 'PCI_DSS', 'GDPR', 'ISO_27001']
            )
            
        except Exception as e:
            logger.error(f"Error creating default policies: {e}")
    
    async def start(self):
        """Start retention policy manager"""
        try:
            # Start cleanup task
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            
            logger.info("Retention policy manager started")
            
        except Exception as e:
            logger.error(f"Error starting retention policy manager: {e}")
            raise
    
    async def stop(self):
        """Stop retention policy manager"""
        try:
            if self.cleanup_task:
                self.cleanup_task.cancel()
            
            logger.info("Retention policy manager stopped")
            
        except Exception as e:
            logger.error(f"Error stopping retention policy manager: {e}")
    
    async def _cleanup_loop(self):
        """Background cleanup loop"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._perform_cleanup()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(300)
    
    async def _perform_cleanup(self):
        """Perform cleanup based on retention policies"""
        try:
            logger.info("Performing retention policy cleanup")
            
            # In a real implementation, this would:
            # 1. Identify expired audit events
            # 2. Archive events according to policies
            # 3. Delete expired events
            # 4. Update retention status
            
            for policy_name, policy in self.policies.items():
                await self._apply_policy(policy)
            
        except Exception as e:
            logger.error(f"Error performing cleanup: {e}")
    
    async def _apply_policy(self, policy: RetentionPolicyConfig):
        """Apply retention policy"""
        try:
            # Calculate cutoff date
            cutoff_date = datetime.utcnow() - policy.retention_period
            
            # Find events to process
            events_to_archive = []
            events_to_delete = []
            
            # In a real implementation, this would query the audit database
            # For now, we'll just log the policy application
            logger.info(f"Applying policy {policy.policy_name}: retention period {policy.retention_period}")
            
        except Exception as e:
            logger.error(f"Error applying policy {policy.policy_name}: {e}")
    
    def get_policy_for_event(self, event_type: AuditEventType) -> Optional[RetentionPolicyConfig]:
        """Get retention policy for event type"""
        for policy in self.policies.values():
            if event_type in policy.event_types:
                return policy
        return None


class ImmutableAuditSystem:
    """Main immutable audit system coordinator"""
    
    def __init__(self):
        """Initialize immutable audit system"""
        self.log_manager = AppendOnlyLogManager()
        self.tamper_detection = TamperDetectionSystem()
        self.archival_system = SecureArchivalSystem()
        self.retention_manager = RetentionPolicyManager()
        
        self.is_running = False
        self.event_queue = asyncio.Queue()
        self.processing_task: Optional[asyncio.Task] = None
        
        logger.info("Immutable audit system initialized")
    
    async def start(self):
        """Start immutable audit system"""
        try:
            logger.info("Starting immutable audit system")
            
            # Initialize components
            await self.log_manager.initialize()
            await self.tamper_detection.initialize()
            await self.archival_system.initialize()
            await self.retention_manager.start()
            
            # Start event processing
            self.processing_task = asyncio.create_task(self._event_processing_loop())
            
            self.is_running = True
            logger.info("Immutable audit system started successfully")
            
        except Exception as e:
            logger.error(f"Error starting immutable audit system: {e}")
            raise
    
    async def stop(self):
        """Stop immutable audit system"""
        try:
            logger.info("Stopping immutable audit system")
            
            self.is_running = False
            
            # Cancel processing task
            if self.processing_task:
                self.processing_task.cancel()
            
            # Stop components
            await self.retention_manager.stop()
            
            # Close log file
            if self.log_manager.current_log_file:
                self.log_manager.current_log_file.close()
            
            logger.info("Immutable audit system stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping immutable audit system: {e}")
    
    async def _event_processing_loop(self):
        """Event processing loop"""
        while self.is_running:
            try:
                # Get event from queue
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Process event
                await self._process_event(event)
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in event processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_event(self, event: AuditEvent):
        """Process audit event"""
        try:
            # Verify integrity
            if not await self.tamper_detection.verify_event_integrity(event):
                logger.error(f"Event integrity verification failed: {event.event_id}")
                return
            
            # Write to append-only log
            success = await self.log_manager.write_event(event)
            
            if not success:
                logger.error(f"Failed to write event to log: {event.event_id}")
                return
            
            logger.debug(f"Event processed: {event.event_id}")
            
        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {e}")
    
    async def log_event(self, event_type: AuditEventType, severity: AuditSeverity,
                       user_id: Optional[str] = None, session_id: Optional[str] = None,
                       ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                       resource: Optional[str] = None, action: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> str:
        """Log audit event"""
        try:
            # Generate event ID
            event_id = f"audit_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            
            # Create event
            event = AuditEvent(
                event_id=event_id,
                event_type=event_type,
                severity=severity,
                timestamp=datetime.utcnow(),
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                resource=resource,
                action=action,
                details=details or {},
                metadata=metadata or {},
                integrity_hash="",
                previous_hash="",
                sequence_number=0
            )
            
            # Add to queue
            await self.event_queue.put(event)
            
            return event_id
            
        except Exception as e:
            logger.error(f"Error logging event: {e}")
            return ""
    
    async def get_audit_trail(self, user_id: Optional[str] = None,
                            event_type: Optional[AuditEventType] = None,
                            start_time: Optional[datetime] = None,
                            end_time: Optional[datetime] = None,
                            limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit trail"""
        try:
            # In a real implementation, this would query the audit database
            # For now, we'll return an empty list
            logger.info(f"Getting audit trail: user_id={user_id}, event_type={event_type}")
            
            return []
            
        except Exception as e:
            logger.error(f"Error getting audit trail: {e}")
            return []
    
    async def verify_audit_integrity(self, chain_id: Optional[str] = None) -> Dict[str, Any]:
        """Verify audit integrity"""
        try:
            if chain_id:
                # Verify specific chain
                events = await self.log_manager._read_chain_events(chain_id)
                is_valid = await self.tamper_detection.verify_chain_integrity(chain_id, events)
                
                return {
                    'chain_id': chain_id,
                    'is_valid': is_valid,
                    'events_count': len(events),
                    'verification_time': datetime.utcnow().isoformat()
                }
            else:
                # Verify all chains
                results = {}
                for chain_id in self.log_manager.chains.keys():
                    events = await self.log_manager._read_chain_events(chain_id)
                    is_valid = await self.tamper_detection.verify_chain_integrity(chain_id, events)
                    
                    results[chain_id] = {
                        'is_valid': is_valid,
                        'events_count': len(events)
                    }
                
                return {
                    'all_chains': results,
                    'verification_time': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error verifying audit integrity: {e}")
            return {'error': str(e)}
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get system status"""
        try:
            return {
                'is_running': self.is_running,
                'log_manager': {
                    'current_chain_id': self.log_manager.current_chain_id,
                    'sequence_number': self.log_manager.sequence_number,
                    'total_chains': len(self.log_manager.chains),
                    'current_log_file': str(self.log_manager.current_log_path) if self.log_manager.current_log_path else None
                },
                'tamper_detection': {
                    'enabled': self.tamper_detection.detection_enabled,
                    'violation_count': self.tamper_detection.violation_count,
                    'last_verification': self.tamper_detection.last_verification.isoformat(),
                    'verification_history_count': len(self.tamper_detection.verification_history)
                },
                'retention_manager': {
                    'policies_count': len(self.retention_manager.policies),
                    'cleanup_interval': self.retention_manager.cleanup_interval
                },
                'event_queue_size': self.event_queue.qsize()
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {'error': str(e)}


# Global immutable audit system instance
immutable_audit_system = ImmutableAuditSystem()


# API functions
async def initialize_immutable_audit() -> str:
    """Initialize immutable audit system"""
    try:
        await immutable_audit_system.start()
        logger.info("Immutable audit system initialized")
        return "Immutable audit system initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing immutable audit system: {e}")
        return f"Error initializing immutable audit system: {e}"


async def stop_immutable_audit() -> str:
    """Stop immutable audit system"""
    try:
        await immutable_audit_system.stop()
        logger.info("Immutable audit system stopped")
        return "Immutable audit system stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping immutable audit system: {e}")
        return f"Error stopping immutable audit system: {e}"


async def log_audit_event(event_type: str, severity: str = 'info',
                       user_id: Optional[str] = None, session_id: Optional[str] = None,
                       ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                       resource: Optional[str] = None, action: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> str:
    """Log audit event"""
    try:
        event_type_enum = AuditEventType(event_type)
        severity_enum = AuditSeverity(severity)
        
        event_id = await immutable_audit_system.log_event(
            event_type=event_type_enum,
            severity=severity_enum,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource=resource,
            action=action,
            details=details,
            metadata=metadata
        )
        
        return event_id
        
    except Exception as e:
        logger.error(f"Error logging audit event: {e}")
        return f"Error logging audit event: {e}"


async def get_audit_trail(user_id: Optional[str] = None,
                        event_type: Optional[str] = None,
                        start_time: Optional[str] = None,
                        end_time: Optional[str] = None,
                        limit: int = 100) -> List[Dict[str, Any]]:
    """Get audit trail"""
    try:
        event_type_enum = AuditEventType(event_type) if event_type else None
        start_dt = datetime.fromisoformat(start_time) if start_time else None
        end_dt = datetime.fromisoformat(end_time) if end_time else None
        
        return await immutable_audit_system.get_audit_trail(
            user_id=user_id,
            event_type=event_type_enum,
            start_time=start_dt,
            end_time=end_dt,
            limit=limit
        )
        
    except Exception as e:
        logger.error(f"Error getting audit trail: {e}")
        return []


async def verify_audit_integrity(chain_id: Optional[str] = None) -> Dict[str, Any]:
    """Verify audit integrity"""
    try:
        return await immutable_audit_system.verify_audit_integrity(chain_id)
    except Exception as e:
        logger.error(f"Error verifying audit integrity: {e}")
        return {'error': str(e)}


async def get_audit_system_status() -> Dict[str, Any]:
    """Get audit system status"""
    try:
        return await immutable_audit_system.get_system_status()
    except Exception as e:
        logger.error(f"Error getting audit system status: {e}")
        return {'error': str(e)}


# Initialize immutable audit system
async def initialize_audit_system() -> str:
    """Initialize audit system"""
    try:
        await initialize_immutable_audit()
        logger.info("Audit system initialized")
        return "Audit system initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing audit system: {e}")
        return f"Error initializing audit system: {e}"


# Cleanup function
async def cleanup_audit_system() -> str:
    """Cleanup audit system"""
    try:
        await stop_immutable_audit()
        logger.info("Audit system cleaned up")
        return "Audit system cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up audit system: {e}")
        return f"Error cleaning up audit system: {e}"
