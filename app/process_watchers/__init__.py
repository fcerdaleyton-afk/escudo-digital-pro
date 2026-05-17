#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Process Watchers Package
Advanced process monitoring and analysis
"""

from .process_analyzer import (
    ProcessAnalyzer, ProcessThreat, ProcessThreatType, ProcessSignature,
    process_analyzer, analyze_process, get_process_history, get_all_threats,
    get_analyzer_statistics, add_process_to_whitelist, remove_process_from_whitelist
)

__all__ = [
    'ProcessAnalyzer',
    'ProcessThreat',
    'ProcessThreatType',
    'ProcessSignature',
    'process_analyzer',
    'analyze_process',
    'get_process_history',
    'get_all_threats',
    'get_analyzer_statistics',
    'add_process_to_whitelist',
    'remove_process_from_whitelist'
]
