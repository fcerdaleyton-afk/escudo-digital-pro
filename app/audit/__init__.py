#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Immutable Audit Strategy Package
Comprehensive immutable logging with tamper detection and secure archival
"""

from .immutable_audit import (
    ImmutableAuditSystem, AuditEventType, AuditSeverity, RetentionPolicy,
    initialize_immutable_audit, stop_immutable_audit, log_audit_event,
    get_audit_trail, verify_audit_integrity, get_audit_system_status,
    initialize_audit_system, cleanup_audit_system
)

__all__ = [
    'ImmutableAuditSystem',
    'AuditEventType',
    'AuditSeverity', 
    'RetentionPolicy',
    'initialize_immutable_audit',
    'stop_immutable_audit',
    'log_audit_event',
    'get_audit_trail',
    'verify_audit_integrity',
    'get_audit_system_status',
    'initialize_audit_system',
    'cleanup_audit_system'
]
