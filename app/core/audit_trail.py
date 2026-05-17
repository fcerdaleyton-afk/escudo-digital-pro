"""
MARY V5 SHIELD CORE - Audit Trail System
Comprehensive audit tracking for security and compliance
"""

import os
import json
import time
import hashlib
import sqlite3
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor

from app.core.dependencies import logger
from app.core.logging_config import get_structured_logger


class AuditEventType(Enum):
    """Audit event types"""
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_GENERATED = "token_generated"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    ADMIN_ACTION = "admin_action"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_EVENT = "security_event"
    THREAT_DETECTED = "threat_detected"
    API_ACCESS = "api_access"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_ERROR = "system_error"
    COMPLIANCE_CHECK = "compliance_check"


class AuditSeverity(Enum):
    """Audit event severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditStatus(Enum):
    """Audit event status"""
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"
    BLOCKED = "blocked"


@dataclass
class AuditEvent:
    """Audit event data structure"""
    id: str = field(default_factory=lambda: str(int(time.time() * 1000000)))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: AuditEventType = AuditEventType.API_ACCESS
    severity: AuditSeverity = AuditSeverity.INFO
    status: AuditStatus = AuditStatus.SUCCESS
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    compliance_tags: List[str] = field(default_factory=list)
    retention_days: int = 2555  # 7 years default
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create audit event from dictionary"""
        data = data.copy()
        data['event_type'] = AuditEventType(data['event_type'])
        data['severity'] = AuditSeverity(data['severity'])
        data['status'] = AuditStatus(data['status'])
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


class AuditDatabase:
    """Audit trail database with SQLite backend"""
    
    def __init__(self, db_path: str = None):
        self.enabled = os.getenv("AUDIT_DATABASE_ENABLED", "true").lower() == "true"
        
        if db_path is None:
            db_path = os.getenv("AUDIT_DB_PATH", "/app/data/audit.db")
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-db")
        
        # Initialize database
        self._init_database()
        
        logger.info("Audit database initialized", enabled=self.enabled, db_path=str(self.db_path))
    
    def _init_database(self):
        """Initialize SQLite database"""
        if not self.enabled:
            return
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Create audit_events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                user_id TEXT,
                session_id TEXT,
                correlation_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                resource TEXT,
                action TEXT,
                result TEXT,
                details TEXT,
                metadata TEXT,
                risk_score REAL,
                compliance_tags TEXT,
                retention_days INTEGER DEFAULT 2555
            )
        """)
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_risk_score ON audit_events(risk_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_correlation_id ON audit_events(correlation_id)")
        
        conn.commit()
        conn.close()
    
    async def store_event(self, event: AuditEvent) -> bool:
        """Store audit event in database"""
        if not self.enabled:
            return False
        
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self.executor, self._store_event_sync, event)
            return True
        except Exception as e:
            logger.error("Failed to store audit event", error=str(e))
            return False
    
    def _store_event_sync(self, event: AuditEvent):
        """Synchronous event storage"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO audit_events 
            (id, timestamp, event_type, severity, status, user_id, session_id, 
             correlation_id, ip_address, user_agent, resource, action, result, 
             details, metadata, risk_score, compliance_tags, retention_days)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.id,
            event.timestamp.isoformat(),
            event.event_type.value,
            event.severity.value,
            event.status.value,
            event.user_id,
            event.session_id,
            event.correlation_id,
            event.ip_address,
            event.user_agent,
            event.resource,
            event.action,
            event.result,
            json.dumps(event.details),
            json.dumps(event.metadata),
            event.risk_score,
            json.dumps(event.compliance_tags),
            event.retention_days
        ))
        
        conn.commit()
        conn.close()
    
    async def get_events(self, limit: int = 100, offset: int = 0, 
                        user_id: str = None, event_type: str = None,
                        severity: str = None, start_time: datetime = None,
                        end_time: datetime = None) -> List[AuditEvent]:
        """Get audit events with filtering"""
        if not self.enabled:
            return []
        
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.executor, self._get_events_sync, 
                limit, offset, user_id, event_type, severity, start_time, end_time
            )
        except Exception as e:
            logger.error("Failed to get audit events", error=str(e))
            return []
    
    def _get_events_sync(self, limit: int, offset: int, user_id: str = None,
                        event_type: str = None, severity: str = None,
                        start_time: datetime = None, end_time: datetime = None) -> List[AuditEvent]:
        """Synchronous event retrieval"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Build query
        query = "SELECT * FROM audit_events WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = AuditEvent(
                id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                event_type=AuditEventType(row[2]),
                severity=AuditSeverity(row[3]),
                status=AuditStatus(row[4]),
                user_id=row[5],
                session_id=row[6],
                correlation_id=row[7],
                ip_address=row[8],
                user_agent=row[9],
                resource=row[10],
                action=row[11],
                result=row[12],
                details=json.loads(row[13]) if row[13] else {},
                metadata=json.loads(row[14]) if row[14] else {},
                risk_score=row[15],
                compliance_tags=json.loads(row[16]) if row[16] else [],
                retention_days=row[17]
            )
            events.append(event)
        
        return events
    
    async def cleanup_expired_events(self):
        """Clean up expired audit events"""
        if not self.enabled:
            return
        
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self.executor, self._cleanup_expired_events_sync)
            logger.info("Audit cleanup completed")
        except Exception as e:
            logger.error("Audit cleanup failed", error=str(e))
    
    def _cleanup_expired_events_sync(self):
        """Synchronous cleanup of expired events"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Calculate cutoff date
        cutoff_date = datetime.utcnow() - timedelta(days=2555)  # 7 years ago
        
        cursor.execute("""
            DELETE FROM audit_events 
            WHERE timestamp < ?
        """, (cutoff_date.isoformat(),))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} expired audit events")
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        if not self.enabled:
            return {"enabled": False}
        
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Total events
            cursor.execute("SELECT COUNT(*) FROM audit_events")
            total_events = cursor.fetchone()[0]
            
            # Events by type
            cursor.execute("SELECT event_type, COUNT(*) FROM audit_events GROUP BY event_type")
            events_by_type = dict(cursor.fetchall())
            
            # Events by severity
            cursor.execute("SELECT severity, COUNT(*) FROM audit_events GROUP BY severity")
            events_by_severity = dict(cursor.fetchall())
            
            # Recent events (last 24 hours)
            yesterday = datetime.utcnow() - timedelta(days=1)
            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE timestamp >= ?", (yesterday.isoformat(),))
            recent_events = cursor.fetchone()[0]
            
            # High risk events
            cursor.execute("SELECT COUNT(*) FROM audit_events WHERE risk_score >= 0.7")
            high_risk_events = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "enabled": True,
                "database_path": str(self.db_path),
                "total_events": total_events,
                "events_by_type": events_by_type,
                "events_by_severity": events_by_severity,
                "recent_events_24h": recent_events,
                "high_risk_events": high_risk_events
            }
            
        except Exception as e:
            logger.error("Failed to get database stats", error=str(e))
            return {"enabled": True, "error": str(e)}


class AuditTrailManager:
    """Main audit trail manager"""
    
    def __init__(self):
        self.enabled = os.getenv("AUDIT_TRAIL_ENABLED", "true").lower() == "true"
        
        # Initialize components
        self.database = AuditDatabase()
        self.structured_logger = get_structured_logger("audit")
        
        # Event queue for batch processing
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.batch_size = int(os.getenv("AUDIT_BATCH_SIZE", "100"))
        self.batch_timeout = int(os.getenv("AUDIT_BATCH_TIMEOUT", "5"))  # seconds
        
        # Background processing
        self.processing_task = None
        self.cleanup_task = None
        
        # Statistics
        self.audit_stats = {
            "events_logged": 0,
            "events_by_type": defaultdict(int),
            "events_by_severity": defaultdict(int),
            "events_by_status": defaultdict(int),
            "batch_processed": 0,
            "errors": 0
        }
        
        # Compliance tracking
        self.compliance_requirements = self._load_compliance_requirements()
        
        logger.info("Audit trail manager initialized", enabled=self.enabled)
    
    def _load_compliance_requirements(self) -> Dict[str, Any]:
        """Load compliance requirements"""
        return {
            "gdpr": {
                "data_access_logging": True,
                "user_consent_tracking": True,
                "data_retention_limits": True,
                "right_to_be_forgotten": True
            },
            "hipaa": {
                "phi_access_logging": True,
                "audit_trail_integrity": True,
                "user_authentication_logging": True
            },
            "pci_dss": {
                "card_data_access": True,
                "authentication_logging": True,
                "network_monitoring": True
            },
            "sox": {
                "financial_data_access": True,
                "configuration_changes": True,
                "admin_action_logging": True
            }
        }
    
    async def start(self):
        """Start audit trail services"""
        if not self.enabled:
            return
        
        # Start event processing
        self.processing_task = asyncio.create_task(self._process_events())
        
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._periodic_cleanup())
        
        logger.info("Audit trail services started")
    
    async def stop(self):
        """Stop audit trail services"""
        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Audit trail services stopped")
    
    async def log_event(self, event_type: AuditEventType, severity: AuditSeverity = AuditSeverity.INFO,
                       status: AuditStatus = AuditStatus.SUCCESS, user_id: str = None,
                       session_id: str = None, correlation_id: str = None,
                       ip_address: str = None, user_agent: str = None,
                       resource: str = None, action: str = None, result: str = None,
                       details: Dict[str, Any] = None, metadata: Dict[str, Any] = None,
                       risk_score: float = 0.0, compliance_tags: List[str] = None) -> str:
        """Log audit event"""
        if not self.enabled:
            return ""
        
        # Create audit event
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            status=status,
            user_id=user_id,
            session_id=session_id,
            correlation_id=correlation_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource=resource,
            action=action,
            result=result,
            details=details or {},
            metadata=metadata or {},
            risk_score=risk_score,
            compliance_tags=compliance_tags or []
        )
        
        # Calculate risk score if not provided
        if risk_score == 0.0:
            event.risk_score = self._calculate_risk_score(event)
        
        # Add to queue
        try:
            await self.event_queue.put(event)
            self.audit_stats["events_logged"] += 1
            self.audit_stats["events_by_type"][event_type.value] += 1
            self.audit_stats["events_by_severity"][severity.value] += 1
            self.audit_stats["events_by_status"][status.value] += 1
            
            return event.id
        except asyncio.QueueFull:
            self.audit_stats["errors"] += 1
            logger.warning("Audit event queue full, dropping event")
            return ""
    
    def _calculate_risk_score(self, event: AuditEvent) -> float:
        """Calculate risk score for audit event"""
        base_score = 0.0
        
        # Severity-based scoring
        severity_scores = {
            AuditSeverity.INFO: 0.1,
            AuditSeverity.WARNING: 0.3,
            AuditSeverity.ERROR: 0.6,
            AuditSeverity.CRITICAL: 0.9
        }
        base_score += severity_scores.get(event.severity, 0.1)
        
        # Event-type-based scoring
        high_risk_events = {
            AuditEventType.LOGIN_FAILURE,
            AuditEventType.PRIVILEGE_ESCALATION,
            AuditEventType.ADMIN_ACTION,
            AuditEventType.SECURITY_EVENT,
            AuditEventType.THREAT_DETECTED,
            AuditEventType.CONFIGURATION_CHANGE
        }
        
        if event.event_type in high_risk_events:
            base_score += 0.3
        
        # Status-based scoring
        if event.status == AuditStatus.FAILURE:
            base_score += 0.2
        elif event.status == AuditStatus.BLOCKED:
            base_score += 0.4
        
        # IP-based scoring (suspicious IPs)
        if event.ip_address and self._is_suspicious_ip(event.ip_address):
            base_score += 0.2
        
        # User-based scoring (admin users)
        if event.user_id and self._is_admin_user(event.user_id):
            base_score += 0.1
        
        return min(1.0, base_score)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        # Mock implementation - in production, use threat intelligence
        suspicious_patterns = ["192.168.", "10.", "172.16.", "127.0.0.1"]
        return any(ip.startswith(pattern) for pattern in suspicious_patterns)
    
    def _is_admin_user(self, user_id: str) -> bool:
        """Check if user is admin"""
        # Mock implementation - in production, check user roles
        admin_patterns = ["admin", "root", "administrator", "system"]
        return any(pattern in user_id.lower() for pattern in admin_patterns)
    
    async def _process_events(self):
        """Process audit events in batches"""
        while True:
            try:
                # Collect batch of events
                batch = []
                deadline = time.time() + self.batch_timeout
                
                while len(batch) < self.batch_size and time.time() < deadline:
                    try:
                        event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                        batch.append(event)
                    except asyncio.TimeoutError:
                        break
                
                if batch:
                    # Process batch
                    await self._process_batch(batch)
                    self.audit_stats["batch_processed"] += 1
                
            except Exception as e:
                self.audit_stats["errors"] += 1
                logger.error("Audit event processing error", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_batch(self, batch: List[AuditEvent]):
        """Process batch of audit events"""
        # Store in database
        for event in batch:
            await self.database.store_event(event)
        
        # Log to structured logger
        for event in batch:
            self.structured_logger.audit(
                f"{event.event_type.value}: {event.action or 'N/A'}",
                details={
                    "event_id": event.id,
                    "user_id": event.user_id,
                    "resource": event.resource,
                    "action": event.action,
                    "result": event.result,
                    "risk_score": event.risk_score,
                    "ip_address": event.ip_address
                }
            )
        
        # Check compliance requirements
        for event in batch:
            await self._check_compliance(event)
    
    async def _check_compliance(self, event: AuditEvent):
        """Check compliance requirements for event"""
        for standard, requirements in self.compliance_requirements.items():
            for requirement, enabled in requirements.items():
                if enabled and self._check_compliance_requirement(event, requirement):
                    # Add compliance tag
                    if standard not in event.compliance_tags:
                        event.compliance_tags.append(standard)
    
    def _check_compliance_requirement(self, event: AuditEvent, requirement: str) -> bool:
        """Check specific compliance requirement"""
        if requirement == "data_access_logging":
            return event.event_type in [AuditEventType.DATA_ACCESS, AuditEventType.DATA_MODIFICATION]
        elif requirement == "user_authentication_logging":
            return event.event_type in [AuditEventType.LOGIN_ATTEMPT, AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILURE]
        elif requirement == "admin_action_logging":
            return event.event_type == AuditEventType.ADMIN_ACTION
        elif requirement == "configuration_changes":
            return event.event_type == AuditEventType.CONFIGURATION_CHANGE
        
        return False
    
    async def _periodic_cleanup(self):
        """Periodic cleanup of expired events"""
        while True:
            try:
                # Wait for cleanup interval (daily)
                await asyncio.sleep(86400)  # 24 hours
                
                # Clean up expired events
                await self.database.cleanup_expired_events()
                
            except Exception as e:
                logger.error("Periodic cleanup error", error=str(e))
                await asyncio.sleep(3600)  # 1 hour on error
    
    async def get_audit_events(self, **kwargs) -> List[Dict[str, Any]]:
        """Get audit events"""
        events = await self.database.get_events(**kwargs)
        return [event.to_dict() for event in events]
    
    async def get_audit_summary(self, days: int = 30) -> Dict[str, Any]:
        """Get audit summary for specified period"""
        start_time = datetime.utcnow() - timedelta(days=days)
        events = await self.database.get_events(
            limit=10000, start_time=start_time
        )
        
        # Calculate summary statistics
        summary = {
            "period_days": days,
            "total_events": len(events),
            "events_by_type": defaultdict(int),
            "events_by_severity": defaultdict(int),
            "events_by_status": defaultdict(int),
            "unique_users": len(set(e.user_id for e in events if e.user_id)),
            "high_risk_events": len([e for e in events if e.risk_score >= 0.7]),
            "compliance_coverage": defaultdict(int)
        }
        
        for event in events:
            summary["events_by_type"][event.event_type.value] += 1
            summary["events_by_severity"][event.severity.value] += 1
            summary["events_by_status"][event.status.value] += 1
            
            for tag in event.compliance_tags:
                summary["compliance_coverage"][tag] += 1
        
        return dict(summary)
    
    def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit trail statistics"""
        return {
            "enabled": self.enabled,
            **self.audit_stats,
            "database_stats": self.database.get_database_stats(),
            "queue_size": self.event_queue.qsize(),
            "compliance_requirements": self.compliance_requirements
        }


# Global audit trail manager
audit_trail_manager = AuditTrailManager()


async def start_audit_trail():
    """Start audit trail services"""
    await audit_trail_manager.start()


async def stop_audit_trail():
    """Stop audit trail services"""
    await audit_trail_manager.stop()


async def log_audit_event(event_type: AuditEventType, **kwargs) -> str:
    """Log audit event"""
    return await audit_trail_manager.log_event(event_type, **kwargs)


async def get_audit_events(**kwargs) -> List[Dict[str, Any]]:
    """Get audit events"""
    return await audit_trail_manager.get_audit_events(**kwargs)


async def get_audit_summary(days: int = 30) -> Dict[str, Any]:
    """Get audit summary"""
    return await audit_trail_manager.get_audit_summary(days)


def get_audit_stats() -> Dict[str, Any]:
    """Get audit trail statistics"""
    return audit_trail_manager.get_audit_stats()
