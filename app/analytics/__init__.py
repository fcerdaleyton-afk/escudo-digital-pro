#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Behavioral Analytics Package
Defensive analytics for behavioral anomaly detection and threat scoring
"""

from .behavioral_anomaly_engine import (
    BehavioralAnomalyEngine,
    initialize_behavioral_anomaly_engine,
    stop_behavioral_anomaly_engine,
    process_behavioral_request,
    process_behavioral_authentication,
    get_behavioral_anomaly_summary,
    get_traffic_baseline,
    get_threat_scoring_status,
    get_adaptive_severity_status
)

__all__ = [
    'BehavioralAnomalyEngine',
    'initialize_behavioral_anomaly_engine',
    'stop_behavioral_anomaly_engine',
    'process_behavioral_request',
    'process_behavioral_authentication',
    'get_behavioral_anomaly_summary',
    'get_traffic_baseline',
    'get_threat_scoring_status',
    'get_adaptive_severity_status'
]
