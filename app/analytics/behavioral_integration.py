#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Behavioral Analytics Integration
Unified interface for behavioral anomaly detection and defensive analytics
"""

import os
import sys
import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from dataclasses import dataclass, field

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import behavioral analytics components
from .behavioral_anomaly_engine import (
    BehavioralAnomalyEngine, AnomalyType, AlertSeverity, ThreatLevel,
    initialize_behavioral_anomaly_engine, stop_behavioral_anomaly_engine,
    process_behavioral_request, process_behavioral_authentication,
    get_behavioral_anomaly_summary, get_traffic_baseline,
    get_threat_scoring_status, get_adaptive_severity_status
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/behavioral_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class BehavioralAnalyticsCoordinator:
    """Coordinator for all behavioral analytics components"""
    
    def __init__(self):
        """Initialize behavioral analytics coordinator"""
        self.anomaly_engine = BehavioralAnomalyEngine()
        self.is_running: bool = False
        self.start_time: datetime = datetime.utcnow()
        
        # Analytics configuration
        self.config = {
            'enable_traffic_learning': True,
            'enable_pattern_detection': True,
            'enable_auth_detection': True,
            'enable_geo_detection': True,
            'enable_threat_scoring': True,
            'enable_adaptive_severity': True,
            'learning_threshold': 100,
            'anomaly_threshold': 0.7,
            'threat_threshold': 0.6,
            'alert_threshold': 0.5
        }
        
        # Statistics
        self.stats = {
            'total_requests_processed': 0,
            'total_authentications_processed': 0,
            'total_anomalies_detected': 0,
            'total_threats_detected': 0,
            'total_alerts_generated': 0,
            'false_positive_rate': 0.0,
            'detection_accuracy': 0.0,
            'average_detection_time': 0.0
        }
        
        logger.info("Behavioral analytics coordinator initialized")
    
    async def start(self):
        """Start behavioral analytics coordinator"""
        logger.info("Starting behavioral analytics coordinator")
        
        try:
            # Initialize anomaly engine
            await initialize_behavioral_anomaly_engine()
            self.is_running = True
            self.start_time = datetime.utcnow()
            
            logger.info("Behavioral analytics coordinator started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error starting behavioral analytics coordinator: {e}")
            return False
    
    async def stop(self):
        """Stop behavioral analytics coordinator"""
        logger.info("Stopping behavioral analytics coordinator")
        
        try:
            # Stop anomaly engine
            await stop_behavioral_anomaly_engine()
            self.is_running = False
            
            logger.info("Behavioral analytics coordinator stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping behavioral analytics coordinator: {e}")
            return False
    
    async def process_request_analytics(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process request for behavioral analytics"""
        try:
            if not self.is_running:
                return {'error': 'Behavioral analytics not running'}
            
            start_time = time.time()
            
            # Extract request data
            endpoint = request_data.get('endpoint', '')
            method = request_data.get('method', 'GET')
            response_time = request_data.get('response_time', 0.0)
            payload_size = request_data.get('payload_size', 0)
            user_agent = request_data.get('user_agent', '')
            status_code = request_data.get('status_code', 200)
            user_id = request_data.get('user_id')
            ip_address = request_data.get('ip_address', '')
            location = request_data.get('location', {})
            timestamp = datetime.fromisoformat(request_data.get('timestamp', datetime.utcnow().isoformat()))
            
            # Process through behavioral engine
            result = await process_behavioral_request(
                endpoint, method, response_time, payload_size, user_agent, status_code,
                user_id, ip_address, location
            )
            
            # Update statistics
            self.stats['total_requests_processed'] += 1
            processing_time = time.time() - start_time
            self.stats['average_detection_time'] = (
                (self.stats['average_detection_time'] * (self.stats['total_requests_processed'] - 1) + processing_time) /
                self.stats['total_requests_processed']
            )
            
            return {
                'processed': True,
                'result': result,
                'processing_time': processing_time,
                'timestamp': timestamp.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error processing request analytics: {e}")
            return {'error': str(e)}
    
    async def process_authentication_analytics(self, auth_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process authentication for behavioral analytics"""
        try:
            if not self.is_running:
                return {'error': 'Behavioral analytics not running'}
            
            start_time = time.time()
            
            # Extract authentication data
            user_id = auth_data.get('user_id', '')
            success = auth_data.get('success', True)
            ip_address = auth_data.get('ip_address', '')
            user_agent = auth_data.get('user_agent', '')
            location = auth_data.get('location', {})
            timestamp = datetime.fromisoformat(auth_data.get('timestamp', datetime.utcnow().isoformat()))
            
            # Process through behavioral engine
            result = await process_behavioral_authentication(
                user_id, success, ip_address, user_agent, location
            )
            
            # Update statistics
            self.stats['total_authentications_processed'] += 1
            processing_time = time.time() - start_time
            self.stats['average_detection_time'] = (
                (self.stats['average_detection_time'] * (self.stats['total_authentications_processed'] - 1) + processing_time) /
                self.stats['total_authentications_processed']
            )
            
            return {
                'processed': True,
                'result': result,
                'processing_time': processing_time,
                'timestamp': timestamp.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error processing authentication analytics: {e}")
            return {'error': str(e)}
    
    async def get_analytics_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive behavioral analytics dashboard"""
        try:
            # Get anomaly summary
            anomaly_summary = await get_behavioral_anomaly_summary()
            
            # Get traffic baseline
            traffic_baseline = await get_traffic_baseline()
            
            # Get threat scoring status
            threat_status = await get_threat_scoring_status()
            
            # Get adaptive severity status
            severity_status = await get_adaptive_severity_status()
            
            # Calculate uptime
            uptime = (datetime.utcnow() - self.start_time).total_seconds()
            
            # Calculate detection rates
            if self.stats['total_requests_processed'] > 0:
                anomaly_rate = self.stats['total_anomalies_detected'] / self.stats['total_requests_processed']
                threat_rate = self.stats['total_threats_detected'] / self.stats['total_requests_processed']
                alert_rate = self.stats['total_alerts_generated'] / self.stats['total_requests_processed']
            else:
                anomaly_rate = 0.0
                threat_rate = 0.0
                alert_rate = 0.0
            
            return {
                'system_status': {
                    'is_running': self.is_running,
                    'uptime_seconds': uptime,
                    'start_time': self.start_time.isoformat()
                },
                'statistics': self.stats,
                'detection_rates': {
                    'anomaly_detection_rate': anomaly_rate,
                    'threat_detection_rate': threat_rate,
                    'alert_generation_rate': alert_rate
                },
                'anomaly_summary': anomaly_summary,
                'traffic_baseline': traffic_baseline,
                'threat_scoring': threat_status,
                'adaptive_severity': severity_status,
                'performance': {
                    'average_detection_time': self.stats['average_detection_time'],
                    'requests_per_second': self.stats['total_requests_processed'] / max(uptime, 1),
                    'authentications_per_second': self.stats['total_authentications_processed'] / max(uptime, 1)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting analytics dashboard: {e}")
            return {'error': str(e)}
    
    async def get_user_behavior_profile(self, user_id: str) -> Dict[str, Any]:
        """Get user behavior profile"""
        try:
            # Get user-specific data from anomaly engine
            user_anomalies = [
                event for event in self.anomaly_engine.anomaly_events
                if event.user_id == user_id
            ]
            
            # Calculate user metrics
            total_anomalies = len(user_anomalies)
            recent_anomalies = [
                event for event in user_anomalies
                if (datetime.utcnow() - event.timestamp).total_seconds() <= 86400  # 24 hours
            ]
            
            # Group by anomaly type
            anomaly_types = {}
            for event in user_anomalies:
                anomaly_type = event.anomaly_type.value
                if anomaly_type not in anomaly_types:
                    anomaly_types[anomaly_type] = 0
                anomaly_types[anomaly_type] += 1
            
            # Calculate risk score
            if user_anomalies:
                avg_threat_score = sum(event.threat_score for event in user_anomalies) / len(user_anomalies)
                max_threat_score = max(event.threat_score for event in user_anomalies)
            else:
                avg_threat_score = 0.0
                max_threat_score = 0.0
            
            return {
                'user_id': user_id,
                'total_anomalies': total_anomalies,
                'recent_anomalies': len(recent_anomalies),
                'anomaly_types': anomaly_types,
                'risk_metrics': {
                    'average_threat_score': avg_threat_score,
                    'max_threat_score': max_threat_score,
                    'risk_level': self._calculate_risk_level(avg_threat_score, max_threat_score)
                },
                'behavioral_patterns': {
                    'most_common_anomaly': max(anomaly_types.items(), key=lambda x: x[1])[0] if anomaly_types else None,
                    'anomaly_frequency': total_anomalies / max(1, (datetime.utcnow() - self.start_time).total_seconds() / 86400)
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting user behavior profile: {e}")
            return {'error': str(e)}
    
    def _calculate_risk_level(self, avg_threat_score: float, max_threat_score: float) -> str:
        """Calculate risk level from threat scores"""
        try:
            if max_threat_score >= 0.8:
                return "critical"
            elif max_threat_score >= 0.6:
                return "high"
            elif avg_threat_score >= 0.4:
                return "medium"
            elif avg_threat_score >= 0.2:
                return "low"
            else:
                return "minimal"
        except Exception:
            return "unknown"
    
    async def get_system_health_metrics(self) -> Dict[str, Any]:
        """Get system health metrics"""
        try:
            # Calculate system health score
            if self.stats['total_requests_processed'] > 0:
                error_rate = 0.0  # No explicit error tracking in current implementation
                detection_rate = self.stats['total_anomalies_detected'] / self.stats['total_requests_processed']
                accuracy = 1.0 - self.stats['false_positive_rate']
                
                # Health score based on detection accuracy and reasonable anomaly rate
                health_score = accuracy * 0.7 + min(1.0, detection_rate * 10) * 0.3
            else:
                health_score = 1.0
            
            # Get component status
            component_status = {
                'anomaly_engine': 'healthy' if self.is_running else 'stopped',
                'traffic_learner': 'healthy',
                'pattern_detector': 'healthy',
                'auth_detector': 'healthy',
                'geo_detector': 'healthy',
                'threat_scorer': 'healthy',
                'alert_severity': 'healthy'
            }
            
            return {
                'overall_health_score': health_score,
                'component_status': component_status,
                'system_metrics': {
                    'uptime': (datetime.utcnow() - self.start_time).total_seconds(),
                    'total_requests': self.stats['total_requests_processed'],
                    'total_authentications': self.stats['total_authentications_processed'],
                    'total_anomalies': self.stats['total_anomalies_detected'],
                    'detection_accuracy': self.stats['detection_accuracy'],
                    'false_positive_rate': self.stats['false_positive_rate']
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting system health metrics: {e}")
            return {'error': str(e)}
    
    async def update_configuration(self, config_updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update behavioral analytics configuration"""
        try:
            updated_keys = []
            
            for key, value in config_updates.items():
                if key in self.config:
                    self.config[key] = value
                    updated_keys.append(key)
            
            return {
                'updated_keys': updated_keys,
                'current_config': self.config
            }
            
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
            return {'error': str(e)}
    
    async def get_anomaly_trends(self, hours: int = 24) -> Dict[str, Any]:
        """Get anomaly trends over time"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Filter anomalies by time
            recent_anomalies = [
                event for event in self.anomaly_engine.anomaly_events
                if event.timestamp > cutoff_time
            ]
            
            # Group by hour
            hourly_counts = {}
            hourly_types = {}
            
            for event in recent_anomalies:
                hour = event.timestamp.hour
                if hour not in hourly_counts:
                    hourly_counts[hour] = 0
                hourly_counts[hour] += 1
                
                if hour not in hourly_types:
                    hourly_types[hour] = {}
                
                anomaly_type = event.anomaly_type.value
                if anomaly_type not in hourly_types[hour]:
                    hourly_types[hour][anomaly_type] = 0
                hourly_types[hour][anomaly_type] += 1
            
            # Calculate trends
            if hourly_counts:
                avg_anomalies_per_hour = sum(hourly_counts.values()) / len(hourly_counts)
                peak_hour = max(hourly_counts.items(), key=lambda x: x[1])[0]
                peak_anomalies = hourly_counts[peak_hour]
            else:
                avg_anomalies_per_hour = 0
                peak_hour = 0
                peak_anomalies = 0
            
            return {
                'period_hours': hours,
                'total_anomalies': len(recent_anomalies),
                'average_per_hour': avg_anomalies_per_hour,
                'peak_hour': peak_hour,
                'peak_anomalies': peak_anomalies,
                'hourly_breakdown': hourly_counts,
                'hourly_types': hourly_types,
                'trend_direction': self._calculate_trend_direction(hourly_counts)
            }
            
        except Exception as e:
            logger.error(f"Error getting anomaly trends: {e}")
            return {'error': str(e)}
    
    def _calculate_trend_direction(self, hourly_counts: Dict[int, int]) -> str:
        """Calculate trend direction from hourly counts"""
        try:
            if len(hourly_counts) < 2:
                return "insufficient_data"
            
            # Sort by hour
            sorted_hours = sorted(hourly_counts.items())
            
            # Calculate trend (simple linear regression)
            n = len(sorted_hours)
            sum_x = sum(range(n))
            sum_y = sum(count for hour, count in sorted_hours)
            sum_xy = sum(i * count for i, (hour, count) in enumerate(sorted_hours))
            sum_x2 = sum(i * i for i in range(n))
            
            if n * sum_x2 - sum_x * sum_x == 0:
                return "stable"
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            
            if slope > 0.1:
                return "increasing"
            elif slope < -0.1:
                return "decreasing"
            else:
                return "stable"
                
        except Exception:
            return "unknown"


# Global behavioral analytics coordinator instance
behavioral_analytics_coordinator = BehavioralAnalyticsCoordinator()


# Unified API functions
async def initialize_behavioral_analytics() -> str:
    """Initialize behavioral analytics system"""
    try:
        success = await behavioral_analytics_coordinator.start()
        
        if success:
            return "Behavioral analytics system initialized successfully"
        else:
            return "Failed to initialize behavioral analytics system"
            
    except Exception as e:
        logger.error(f"Error initializing behavioral analytics: {e}")
        return f"Error initializing behavioral analytics: {e}"


async def stop_behavioral_analytics() -> str:
    """Stop behavioral analytics system"""
    try:
        success = await behavioral_analytics_coordinator.stop()
        
        if success:
            return "Behavioral analytics system stopped successfully"
        else:
            return "Failed to stop behavioral analytics system"
            
    except Exception as e:
        logger.error(f"Error stopping behavioral analytics: {e}")
        return f"Error stopping behavioral analytics: {e}"


async def get_behavioral_analytics_dashboard() -> Dict[str, Any]:
    """Get comprehensive behavioral analytics dashboard"""
    try:
        return await behavioral_analytics_coordinator.get_analytics_dashboard()
    except Exception as e:
        logger.error(f"Error getting behavioral analytics dashboard: {e}")
        return {'error': str(e)}


async def analyze_request_behavior(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze request behavior for anomalies"""
    try:
        return await behavioral_analytics_coordinator.process_request_analytics(request_data)
    except Exception as e:
        logger.error(f"Error analyzing request behavior: {e}")
        return {'error': str(e)}


async def analyze_authentication_behavior(auth_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze authentication behavior for anomalies"""
    try:
        return await behavioral_analytics_coordinator.process_authentication_analytics(auth_data)
    except Exception as e:
        logger.error(f"Error analyzing authentication behavior: {e}")
        return {'error': str(e)}


async def get_user_behavior_profile(user_id: str) -> Dict[str, Any]:
    """Get user behavior profile"""
    try:
        return await behavioral_analytics_coordinator.get_user_behavior_profile(user_id)
    except Exception as e:
        logger.error(f"Error getting user behavior profile: {e}")
        return {'error': str(e)}


async def get_behavioral_system_health() -> Dict[str, Any]:
    """Get behavioral analytics system health"""
    try:
        return await behavioral_analytics_coordinator.get_system_health_metrics()
    except Exception as e:
        logger.error(f"Error getting behavioral system health: {e}")
        return {'error': str(e)}


async def get_anomaly_trends(hours: int = 24) -> Dict[str, Any]:
    """Get anomaly trends over time"""
    try:
        return await behavioral_analytics_coordinator.get_anomaly_trends(hours)
    except Exception as e:
        logger.error(f"Error getting anomaly trends: {e}")
        return {'error': str(e)}


async def update_behavioral_configuration(config_updates: Dict[str, Any]) -> Dict[str, Any]:
    """Update behavioral analytics configuration"""
    try:
        return await behavioral_analytics_coordinator.update_configuration(config_updates)
    except Exception as e:
        logger.error(f"Error updating behavioral configuration: {e}")
        return {'error': str(e)}
