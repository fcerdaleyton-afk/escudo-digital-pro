#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Simplified Application Package
Consolidated and simplified architecture for maintainability
"""

from .simplified_app import (
    SimplifiedApplication, simplified_app,
    start_application, stop_application, handle_request, get_application_status
)

__all__ = [
    'SimplifiedApplication',
    'simplified_app',
    'start_application',
    'stop_application',
    'handle_request',
    'get_application_status'
]
