#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Alerting Package
Comprehensive alerting system with SMTP and WebSocket support
"""

from .alert_manager import (
    AlertManager, Alert, AlertSeverity, AlertStatus,
    alert_manager, start_alert_manager, stop_alert_manager,
    create_alert, get_alerts, get_alert_statistics,
    add_websocket_client, remove_websocket_client,
    initialize_alert_manager, cleanup_alert_manager
)

__all__ = [
    'AlertManager',
    'Alert',
    'AlertSeverity',
    'AlertStatus',
    'alert_manager',
    'start_alert_manager',
    'stop_alert_manager',
    'create_alert',
    'get_alerts',
    'get_alert_statistics',
    'add_websocket_client',
    'remove_websocket_client',
    'initialize_alert_manager',
    'cleanup_alert_manager'
]
