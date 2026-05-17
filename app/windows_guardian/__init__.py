#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Windows Guardian Package
Defensive monitoring and protection for Windows systems
"""

from .windows_guardian import (
    WindowsGuardianCore, SecurityEvent, AlertType, ThreatLevel, ResponseMode,
    windows_guardian, start_windows_guardian, stop_windows_guardian,
    get_guardian_events, get_guardian_statistics, set_response_mode,
    add_alert_callback, initialize_windows_guardian, cleanup_windows_guardian
)

__all__ = [
    'WindowsGuardianCore',
    'SecurityEvent',
    'AlertType',
    'ThreatLevel',
    'ResponseMode',
    'windows_guardian',
    'start_windows_guardian',
    'stop_windows_guardian',
    'get_guardian_events',
    'get_guardian_statistics',
    'set_response_mode',
    'add_alert_callback',
    'initialize_windows_guardian',
    'cleanup_windows_guardian'
]
