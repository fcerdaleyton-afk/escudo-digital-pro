#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Event Watchers Package
Windows Event Log monitoring and analysis
"""

from .event_monitor import (
    EventMonitor, WindowsEvent, SecurityAlert, EventLogType, EventSeverity, SecurityEventType,
    event_monitor, start_event_monitor, stop_event_monitor, get_events, get_security_alerts,
    get_event_statistics, add_event_callback, initialize_event_monitor, cleanup_event_monitor
)

__all__ = [
    'EventMonitor',
    'WindowsEvent',
    'SecurityAlert',
    'EventLogType',
    'EventSeverity',
    'SecurityEventType',
    'event_monitor',
    'start_event_monitor',
    'stop_event_monitor',
    'get_events',
    'get_security_alerts',
    'get_event_statistics',
    'add_event_callback',
    'initialize_event_monitor',
    'cleanup_event_monitor'
]
