#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Behavioral Anomaly Engine
Defensive analytics for behavioral anomaly detection and threat scoring
"""

import os
import sys
import asyncio
import logging
import json
import time
import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque, Counter
import weakref
import numpy as np
from scipy import stats
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/behavioral_anomaly.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Anomaly type enumeration"""
    TRAFFIC_VOLUME = "traffic_volume"
    REQUEST_PATTERN = "request_pattern"
    AUTHENTICATION_BEHAVIOR = "authentication_behavior"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    TIME_PATTERN = "time_pattern"
    USER_BEHAVIOR = "user_behavior"
    SYSTEM_BEHAVIOR = "system_behavior"


class AlertSeverity(Enum):
    """Alert severity enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLevel(Enum):
    """Threat level enumeration"""
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TrafficBaseline:
    """Traffic baseline metrics"""
    avg_requests_per_minute: float
    std_requests_per_minute: float
    avg_response_time: float
    std_response_time: float
    avg_payload_size: float
    std_payload_size: float
    peak_hours: List[int]
    low_hours: List[int]
    weekday_pattern: Dict[str, float]
    weekend_pattern: Dict[str, float]
    user_agent_distribution: Dict[str, float]
    endpoint_distribution: Dict[str, float]
    status_code_distribution: Dict[str, float]
    created_at: datetime
    updated_at: datetime


@dataclass
class RequestPattern:
    """Request pattern metrics"""
    endpoint: str
    method: str
    avg_frequency: float
    std_frequency: float
    avg_response_time: float
    std_response_time: float
    avg_payload_size: float
    std_payload_size: float
    typical_user_agents: List[str]
    typical_status_codes: List[int]
    time_pattern: Dict[str, float]
    created_at: datetime
    updated_at: datetime


@dataclass
class AuthenticationBehavior:
    """Authentication behavior metrics"""
    user_id: str
    avg_login_frequency: float
    std_login_frequency: float
    typical_login_hours: List[int]
    typical_locations: List[str]
    typical_devices: List[str]
    typical_user_agents: List[str]
    avg_session_duration: float
    std_session_duration: float
    failed_login_rate: float
    created_at: datetime
    updated_at: datetime


@dataclass
class GeographicProfile:
    """Geographic profile metrics"""
    user_id: str
    typical_countries: List[str]
    typical_cities: List[str]
    typical_isps: List[str]
    location_velocity: float  # km/hour
    last_location: Optional[Dict[str, Any]]
    location_history: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime


@dataclass
class AnomalyEvent:
    """Anomaly event data"""
    event_id: str
    anomaly_type: AnomalyType
    severity: AlertSeverity
    threat_level: ThreatLevel
    confidence: float
    timestamp: datetime
    user_id: Optional[str]
    ip_address: Optional[str]
    endpoint: Optional[str]
    details: Dict[str, Any]
    baseline_metrics: Dict[str, Any]
    current_metrics: Dict[str, Any]
    deviation_score: float
    adaptive_severity: AlertSeverity
    threat_score: float
    false_positive_probability: float


@dataclass
class AdaptiveThreshold:
    """Adaptive threshold configuration"""
    metric_name: str
    base_threshold: float
    current_threshold: float
    adaptation_rate: float
    min_threshold: float
    max_threshold: float
    last_adjustment: datetime
    adjustment_history: List[Tuple[datetime, float, str]]


class BaselineTrafficLearner:
    """Baseline traffic learning system"""
    
    def __init__(self):
        """Initialize baseline traffic learner"""
        self.traffic_history: deque = deque(maxlen=10000)
        self.hourly_patterns: Dict[int, List[float]] = defaultdict(list)
        self.weekday_patterns: Dict[str, List[float]] = defaultdict(list)
        self.weekend_patterns: Dict[str, List[float]] = defaultdict(list)
        self.baseline: Optional[TrafficBaseline] = None
        self.learning_enabled: bool = True
        self.min_samples: int = 1000
        self.update_interval: int = 3600  # 1 hour
        self.last_update: datetime = datetime.utcnow()
        
        logger.info("Baseline traffic learner initialized")
    
    def add_traffic_data(self, requests_per_minute: float, response_time: float, 
                        payload_size: float, user_agent: str, endpoint: str, 
                        status_code: int, timestamp: datetime):
        """Add traffic data for learning"""
        try:
            traffic_data = {
                'requests_per_minute': requests_per_minute,
                'response_time': response_time,
                'payload_size': payload_size,
                'user_agent': user_agent,
                'endpoint': endpoint,
                'status_code': status_code,
                'timestamp': timestamp,
                'hour': timestamp.hour,
                'weekday': timestamp.strftime('%A'),
                'is_weekend': timestamp.weekday() >= 5
            }
            
            self.traffic_history.append(traffic_data)
            
            # Update patterns
            self.hourly_patterns[timestamp.hour].append(requests_per_minute)
            
            if timestamp.weekday() < 5:
                self.weekday_patterns[timestamp.strftime('%A')].append(requests_per_minute)
            else:
                self.weekend_patterns[timestamp.strftime('%A')].append(requests_per_minute)
            
            # Check if we should update baseline
            if len(self.traffic_history) >= self.min_samples:
                if (datetime.utcnow() - self.last_update).total_seconds() >= self.update_interval:
                    self._update_baseline()
                    
        except Exception as e:
            logger.error(f"Error adding traffic data: {e}")
    
    def _update_baseline(self):
        """Update traffic baseline"""
        try:
            if len(self.traffic_history) < self.min_samples:
                return
            
            # Extract metrics
            requests_per_minute = [d['requests_per_minute'] for d in self.traffic_history]
            response_times = [d['response_time'] for d in self.traffic_history]
            payload_sizes = [d['payload_size'] for d in self.traffic_history]
            
            # Calculate statistics
            avg_rpm = statistics.mean(requests_per_minute)
            std_rpm = statistics.stdev(requests_per_minute) if len(requests_per_minute) > 1 else 0
            
            avg_rt = statistics.mean(response_times)
            std_rt = statistics.stdev(response_times) if len(response_times) > 1 else 0
            
            avg_ps = statistics.mean(payload_sizes)
            std_ps = statistics.stdev(payload_sizes) if len(payload_sizes) > 1 else 0
            
            # Find peak and low hours
            hourly_avg = {hour: statistics.mean(times) if times else 0 
                        for hour, times in self.hourly_patterns.items()}
            
            peak_hours = sorted(hourly_avg.keys(), key=lambda h: hourly_avg[h], reverse=True)[:3]
            low_hours = sorted(hourly_avg.keys(), key=lambda h: hourly_avg[h])[:3]
            
            # Calculate weekday/weekend patterns
            weekday_avg = {}
            weekend_avg = {}
            
            for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']:
                if self.weekday_patterns[day]:
                    weekday_avg[day] = statistics.mean(self.weekday_patterns[day])
            
            for day in ['Saturday', 'Sunday']:
                if self.weekend_patterns[day]:
                    weekend_avg[day] = statistics.mean(self.weekend_patterns[day])
            
            # Calculate distributions
            user_agents = [d['user_agent'] for d in self.traffic_history]
            endpoints = [d['endpoint'] for d in self.traffic_history]
            status_codes = [str(d['status_code']) for d in self.traffic_history]
            
            user_agent_dist = dict(Counter(user_agents))
            endpoint_dist = dict(Counter(endpoints))
            status_code_dist = dict(Counter(status_codes))
            
            # Normalize distributions
            total_ua = sum(user_agent_dist.values())
            total_ep = sum(endpoint_dist.values())
            total_sc = sum(status_code_dist.values())
            
            user_agent_dist = {k: v/total_ua for k, v in user_agent_dist.items()}
            endpoint_dist = {k: v/total_ep for k, v in endpoint_dist.items()}
            status_code_dist = {k: v/total_sc for k, v in status_code_dist.items()}
            
            # Create baseline
            self.baseline = TrafficBaseline(
                avg_requests_per_minute=avg_rpm,
                std_requests_per_minute=std_rpm,
                avg_response_time=avg_rt,
                std_response_time=std_rt,
                avg_payload_size=avg_ps,
                std_payload_size=std_ps,
                peak_hours=peak_hours,
                low_hours=low_hours,
                weekday_pattern=weekday_avg,
                weekend_pattern=weekend_avg,
                user_agent_distribution=user_agent_dist,
                endpoint_distribution=endpoint_dist,
                status_code_distribution=status_code_dist,
                created_at=self.baseline.created_at if self.baseline else datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            self.last_update = datetime.utcnow()
            logger.info(f"Traffic baseline updated with {len(self.traffic_history)} samples")
            
        except Exception as e:
            logger.error(f"Error updating baseline: {e}")
    
    def get_baseline(self) -> Optional[TrafficBaseline]:
        """Get current baseline"""
        return self.baseline
    
    def is_anomalous_traffic(self, current_rpm: float, current_rt: float, 
                            current_ps: float, timestamp: datetime) -> Tuple[bool, float]:
        """Check if current traffic is anomalous"""
        try:
            if not self.baseline:
                return False, 0.0
            
            # Calculate Z-scores
            rpm_z = abs(current_rpm - self.baseline.avg_requests_per_minute) / max(self.baseline.std_requests_per_minute, 1)
            rt_z = abs(current_rt - self.baseline.avg_response_time) / max(self.baseline.std_response_time, 1)
            ps_z = abs(current_ps - self.baseline.avg_payload_size) / max(self.baseline.std_payload_size, 1)
            
            # Time-based adjustments
            hour = timestamp.hour
            is_weekend = timestamp.weekday() >= 5
            
            # Check if it's a peak hour
            if hour in self.baseline.peak_hours:
                rpm_threshold = 3.0  # More lenient during peak hours
            elif hour in self.baseline.low_hours:
                rpm_threshold = 2.0  # Stricter during low hours
            else:
                rpm_threshold = 2.5  # Normal threshold
            
            # Check if it's weekend vs weekday
            if is_weekend and self.baseline.weekend_pattern:
                day_name = timestamp.strftime('%A')
                expected_rpm = self.baseline.weekend_pattern.get(day_name, self.baseline.avg_requests_per_minute)
                rpm_z = abs(current_rpm - expected_rpm) / max(self.baseline.std_requests_per_minute, 1)
            elif not is_weekend and self.baseline.weekday_pattern:
                day_name = timestamp.strftime('%A')
                expected_rpm = self.baseline.weekday_pattern.get(day_name, self.baseline.avg_requests_per_minute)
                rpm_z = abs(current_rpm - expected_rpm) / max(self.baseline.std_requests_per_minute, 1)
            
            # Combined anomaly score
            anomaly_score = (rpm_z * 0.5 + rt_z * 0.3 + ps_z * 0.2)
            
            is_anomalous = anomaly_score > rpm_threshold
            
            return is_anomalous, anomaly_score
            
        except Exception as e:
            logger.error(f"Error checking traffic anomaly: {e}")
            return False, 0.0


class RequestPatternDetector:
    """Request pattern anomaly detection"""
    
    def __init__(self):
        """Initialize request pattern detector"""
        self.patterns: Dict[str, RequestPattern] = {}
        self.request_history: deque = deque(maxlen=10000)
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.model_trained: bool = False
        self.min_samples: int = 500
        self.update_interval: int = 1800  # 30 minutes
        self.last_update: datetime = datetime.utcnow()
        
        logger.info("Request pattern detector initialized")
    
    def add_request(self, endpoint: str, method: str, response_time: float, 
                   payload_size: float, user_agent: str, status_code: int, 
                   timestamp: datetime):
        """Add request data for pattern learning"""
        try:
            request_data = {
                'endpoint': endpoint,
                'method': method,
                'response_time': response_time,
                'payload_size': payload_size,
                'user_agent': user_agent,
                'status_code': status_code,
                'timestamp': timestamp,
                'hour': timestamp.hour
            }
            
            self.request_history.append(request_data)
            
            # Update pattern for this endpoint
            pattern_key = f"{method}:{endpoint}"
            if pattern_key not in self.patterns:
                self.patterns[pattern_key] = RequestPattern(
                    endpoint=endpoint,
                    method=method,
                    avg_frequency=0.0,
                    std_frequency=0.0,
                    avg_response_time=0.0,
                    std_response_time=0.0,
                    avg_payload_size=0.0,
                    std_payload_size=0.0,
                    typical_user_agents=[],
                    typical_status_codes=[],
                    time_pattern={},
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
            
            # Update pattern
            self._update_pattern(pattern_key, request_data)
            
            # Check if we should update model
            if len(self.request_history) >= self.min_samples:
                if (datetime.utcnow() - self.last_update).total_seconds() >= self.update_interval:
                    self._update_model()
                    
        except Exception as e:
            logger.error(f"Error adding request data: {e}")
    
    def _update_pattern(self, pattern_key: str, request_data: Dict[str, Any]):
        """Update request pattern"""
        try:
            pattern = self.patterns[pattern_key]
            
            # Get recent requests for this pattern
            recent_requests = [r for r in self.request_history 
                             if r['endpoint'] == request_data['endpoint'] 
                             and r['method'] == request_data['method'] 
                             and (datetime.utcnow() - r['timestamp']).total_seconds() <= 3600]
            
            if len(recent_requests) < 10:
                return
            
            # Calculate frequency (requests per minute)
            time_span = max(1, (recent_requests[-1]['timestamp'] - recent_requests[0]['timestamp']).total_seconds() / 60)
            frequency = len(recent_requests) / time_span
            
            # Calculate metrics
            response_times = [r['response_time'] for r in recent_requests]
            payload_sizes = [r['payload_size'] for r in recent_requests]
            user_agents = [r['user_agent'] for r in recent_requests]
            status_codes = [r['status_code'] for r in recent_requests]
            
            # Update pattern
            pattern.avg_frequency = frequency
            pattern.std_frequency = statistics.stdev([len(r) for r in 
                                                   [list(g) for k, g in itertools.groupby(
                                                       sorted(recent_requests, key=lambda x: x['timestamp']), 
                                                       key=lambda x: x[0].strftime('%Y-%m-%d %H:%M')
                                                   )]]) if len(recent_requests) > 1 else 0
            pattern.avg_response_time = statistics.mean(response_times)
            pattern.std_response_time = statistics.stdev(response_times) if len(response_times) > 1 else 0
            pattern.avg_payload_size = statistics.mean(payload_sizes)
            pattern.std_payload_size = statistics.stdev(payload_sizes) if len(payload_sizes) > 1 else 0
            
            # Update typical values
            pattern.typical_user_agents = [ua for ua, count in Counter(user_agents).most_common(5)]
            pattern.typical_status_codes = [sc for sc, count in Counter(status_codes).most_common(3)]
            
            # Update time pattern
            hour_counts = Counter([r['hour'] for r in recent_requests])
            total_requests = sum(hour_counts.values())
            pattern.time_pattern = {str(hour): count/total_requests for hour, count in hour_counts.items()}
            
            pattern.updated_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error updating pattern: {e}")
    
    def _update_model(self):
        """Update anomaly detection model"""
        try:
            if len(self.request_history) < self.min_samples:
                return
            
            # Prepare training data
            features = []
            for request in self.request_history:
                pattern_key = f"{request['method']}:{request['endpoint']}"
                pattern = self.patterns.get(pattern_key)
                
                if pattern and pattern.avg_frequency > 0:
                    feature_vector = [
                        request['response_time'],
                        request['payload_size'],
                        pattern.avg_frequency,
                        pattern.avg_response_time,
                        pattern.avg_payload_size
                    ]
                    features.append(feature_vector)
            
            if len(features) < 100:
                return
            
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Train model
            self.isolation_forest.fit(features_scaled)
            self.model_trained = True
            self.last_update = datetime.utcnow()
            
            logger.info(f"Request pattern model updated with {len(features)} samples")
            
        except Exception as e:
            logger.error(f"Error updating model: {e}")
    
    def detect_anomaly(self, endpoint: str, method: str, response_time: float, 
                       payload_size: float, user_agent: str, status_code: int, 
                       timestamp: datetime) -> Tuple[bool, float]:
        """Detect request pattern anomaly"""
        try:
            if not self.model_trained:
                return False, 0.0
            
            pattern_key = f"{method}:{endpoint}"
            pattern = self.patterns.get(pattern_key)
            
            if not pattern or pattern.avg_frequency == 0:
                return False, 0.0
            
            # Prepare feature vector
            feature_vector = [
                response_time,
                payload_size,
                pattern.avg_frequency,
                pattern.avg_response_time,
                pattern.avg_payload_size
            ]
            
            # Scale features
            feature_scaled = self.scaler.transform([feature_vector])
            
            # Predict anomaly
            anomaly_score = -self.isolation_forest.decision_function(feature_scaled)[0]
            is_anomaly = self.isolation_forest.predict(feature_scaled)[0] == -1
            
            # Additional checks
            if user_agent not in pattern.typical_user_agents:
                anomaly_score += 0.5
            
            if status_code not in pattern.typical_status_codes:
                anomaly_score += 0.3
            
            # Time-based check
            hour = str(timestamp.hour)
            expected_frequency = pattern.time_pattern.get(hour, 0.0)
            if expected_frequency > 0 and pattern.avg_frequency > 0:
                frequency_ratio = pattern.avg_frequency / expected_frequency
                if frequency_ratio > 3.0 or frequency_ratio < 0.3:
                    anomaly_score += 0.4
            
            return is_anomaly, anomaly_score
            
        except Exception as e:
            logger.error(f"Error detecting request anomaly: {e}")
            return False, 0.0


class AuthenticationBehaviorDetector:
    """Authentication behavior anomaly detection"""
    
    def __init__(self):
        """Initialize authentication behavior detector"""
        self.user_behaviors: Dict[str, AuthenticationBehavior] = {}
        self.auth_history: deque = deque(maxlen=10000)
        self.failed_login_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.min_samples: int = 50
        self.update_interval: int = 3600  # 1 hour
        self.last_update: datetime = datetime.utcnow()
        
        logger.info("Authentication behavior detector initialized")
    
    def add_authentication_event(self, user_id: str, success: bool, ip_address: str, 
                              user_agent: str, location: Dict[str, Any], 
                              timestamp: datetime):
        """Add authentication event"""
        try:
            auth_event = {
                'user_id': user_id,
                'success': success,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'location': location,
                'timestamp': timestamp,
                'hour': timestamp.hour
            }
            
            self.auth_history.append(auth_event)
            
            # Track failed attempts
            if not success:
                self.failed_login_attempts[user_id].append(auth_event)
            
            # Update user behavior
            self._update_user_behavior(user_id, auth_event)
            
            # Check if we should update baseline
            if len(self.auth_history) >= self.min_samples:
                if (datetime.utcnow() - self.last_update).total_seconds() >= self.update_interval:
                    self._update_all_behaviors()
                    
        except Exception as e:
            logger.error(f"Error adding authentication event: {e}")
    
    def _update_user_behavior(self, user_id: str, auth_event: Dict[str, Any]):
        """Update user behavior profile"""
        try:
            if user_id not in self.user_behaviors:
                self.user_behaviors[user_id] = AuthenticationBehavior(
                    user_id=user_id,
                    avg_login_frequency=0.0,
                    std_login_frequency=0.0,
                    typical_login_hours=[],
                    typical_locations=[],
                    typical_devices=[],
                    typical_user_agents=[],
                    avg_session_duration=0.0,
                    std_session_duration=0.0,
                    failed_login_rate=0.0,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
            
            behavior = self.user_behaviors[user_id]
            
            # Get recent successful logins for this user
            recent_logins = [a for a in self.auth_history 
                           if a['user_id'] == user_id 
                           and a['success'] 
                           and (datetime.utcnow() - a['timestamp']).total_seconds() <= 86400]  # 24 hours
            
            if len(recent_logins) < 5:
                return
            
            # Calculate login frequency (logins per hour)
            time_span = max(1, (recent_logins[-1]['timestamp'] - recent_logins[0]['timestamp']).total_seconds() / 3600)
            frequency = len(recent_logins) / time_span
            
            # Calculate typical login hours
            login_hours = [a['hour'] for a in recent_logins]
            behavior.typical_login_hours = [hour for hour, count in Counter(login_hours).most_common(3)]
            
            # Calculate typical locations
            locations = [a['location']['country'] for a in recent_logins if a['location'].get('country')]
            behavior.typical_locations = [loc for loc, count in Counter(locations).most_common(3)]
            
            # Calculate typical devices
            devices = [a['user_agent'] for a in recent_logins]
            behavior.typical_devices = [device for device, count in Counter(devices).most_common(3)]
            
            # Calculate typical user agents
            behavior.typical_user_agents = [ua for ua, count in Counter(devices).most_common(3)]
            
            # Calculate failed login rate
            total_attempts = len([a for a in self.auth_history if a['user_id'] == user_id])
            failed_attempts = len(self.failed_login_attempts[user_id])
            behavior.failed_login_rate = failed_attempts / max(total_attempts, 1)
            
            # Update behavior
            behavior.avg_login_frequency = frequency
            behavior.std_login_frequency = statistics.stdev([len(list(g)) for k, g in 
                                                          itertools.groupby(
                                                              sorted(recent_logins, key=lambda x: x['timestamp']), 
                                                              key=lambda x: x[0].strftime('%Y-%m-%d')
                                                          )]) if len(recent_logins) > 1 else 0
            
            behavior.updated_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error updating user behavior: {e}")
    
    def _update_all_behaviors(self):
        """Update all user behavior profiles"""
        try:
            for user_id in self.user_behaviors:
                recent_events = [a for a in self.auth_history if a['user_id'] == user_id]
                if recent_events:
                    self._update_user_behavior(user_id, recent_events[-1])
            
            self.last_update = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error updating all behaviors: {e}")
    
    def detect_anomaly(self, user_id: str, success: bool, ip_address: str, 
                       user_agent: str, location: Dict[str, Any], 
                       timestamp: datetime) -> Tuple[bool, float]:
        """Detect authentication behavior anomaly"""
        try:
            behavior = self.user_behaviors.get(user_id)
            
            if not behavior:
                return False, 0.0  # New user, no baseline
            
            anomaly_score = 0.0
            reasons = []
            
            # Check failed login rate
            if not success:
                recent_failed = len([a for a in self.failed_login_attempts[user_id] 
                                   if (timestamp - a['timestamp']).total_seconds() <= 3600])
                if recent_failed > 5:
                    anomaly_score += 1.0
                    reasons.append("High failed login rate")
            
            # Check login frequency
            if behavior.avg_login_frequency > 0:
                recent_logins = len([a for a in self.auth_history 
                                   if a['user_id'] == user_id 
                                   and a['success'] 
                                   and (timestamp - a['timestamp']).total_seconds() <= 3600])
                
                frequency_ratio = recent_logins / behavior.avg_login_frequency
                if frequency_ratio > 5.0:
                    anomaly_score += 0.8
                    reasons.append("Unusual login frequency")
                elif frequency_ratio < 0.1 and behavior.avg_login_frequency > 0.1:
                    anomaly_score += 0.6
                    reasons.append("Abnormal login frequency")
            
            # Check login hour
            if behavior.typical_login_hours:
                if timestamp.hour not in behavior.typical_login_hours:
                    anomaly_score += 0.4
                    reasons.append("Unusual login hour")
            
            # Check location
            if behavior.typical_locations and location.get('country'):
                if location['country'] not in behavior.typical_locations:
                    anomaly_score += 0.7
                    reasons.append("Unusual location")
            
            # Check device/user agent
            if behavior.typical_user_agents:
                if user_agent not in behavior.typical_user_agents:
                    anomaly_score += 0.5
                    reasons.append("Unusual device")
            
            # Check for rapid location changes
            if behavior.typical_locations and location.get('country'):
                recent_locations = [a['location'] for a in self.auth_history 
                                  if a['user_id'] == user_id 
                                  and a['success'] 
                                  and (timestamp - a['timestamp']).total_seconds() <= 3600]
                
                if len(recent_locations) > 1:
                    # Calculate geographic distance (simplified)
                    last_location = recent_locations[-2]
                    current_location = recent_locations[-1]
                    
                    if (last_location.get('country') != current_location.get('country') and
                        behavior.typical_locations and 
                        last_location.get('country') in behavior.typical_locations):
                        anomaly_score += 0.9
                        reasons.append("Rapid geographic change")
            
            is_anomaly = anomaly_score > 0.7
            
            return is_anomaly, anomaly_score
            
        except Exception as e:
            logger.error(f"Error detecting authentication anomaly: {e}")
            return False, 0.0


class GeographicAnomalyDetector:
    """Geographic anomaly detection"""
    
    def __init__(self):
        """Initialize geographic anomaly detector"""
        self.user_profiles: Dict[str, GeographicProfile] = {}
        self.location_history: deque = deque(maxlen=10000)
        self.min_samples: int = 10
        self.max_velocity: float = 1000.0  # km/hour (supersonic flight)
        
        logger.info("Geographic anomaly detector initialized")
    
    def add_location_event(self, user_id: str, ip_address: str, location: Dict[str, Any], 
                          timestamp: datetime):
        """Add location event"""
        try:
            location_event = {
                'user_id': user_id,
                'ip_address': ip_address,
                'location': location,
                'timestamp': timestamp
            }
            
            self.location_history.append(location_event)
            
            # Update user profile
            self._update_user_profile(user_id, location_event)
            
        except Exception as e:
            logger.error(f"Error adding location event: {e}")
    
    def _update_user_profile(self, user_id: str, location_event: Dict[str, Any]):
        """Update user geographic profile"""
        try:
            if user_id not in self.user_profiles:
                self.user_profiles[user_id] = GeographicProfile(
                    user_id=user_id,
                    typical_countries=[],
                    typical_cities=[],
                    typical_isps=[],
                    location_velocity=0.0,
                    last_location=None,
                    location_history=[],
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
            
            profile = self.user_profiles[user_id]
            
            # Add to history
            profile.location_history.append({
                'location': location_event['location'],
                'timestamp': location_event['timestamp'],
                'ip_address': location_event['ip_address']
            })
            
            # Keep only recent history (last 30 days)
            cutoff_time = datetime.utcnow() - timedelta(days=30)
            profile.location_history = [h for h in profile.location_history if h['timestamp'] > cutoff_time]
            
            # Update typical locations
            countries = [h['location'].get('country') for h in profile.location_history if h['location'].get('country')]
            cities = [h['location'].get('city') for h in profile.location_history if h['location'].get('city')]
            isps = [h['location'].get('isp') for h in profile.location_history if h['location'].get('isp')]
            
            profile.typical_countries = [country for country, count in Counter(countries).most_common(5)]
            profile.typical_cities = [city for city, count in Counter(cities).most_common(5)]
            profile.typical_isps = [isp for isp, count in Counter(isps).most_common(5)]
            
            # Update last location
            profile.last_location = location_event
            
            # Calculate location velocity
            if len(profile.location_history) > 1:
                velocity = self._calculate_velocity(profile.location_history[-2:], profile)
                profile.location_velocity = velocity
            
            profile.updated_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error updating user profile: {e}")
    
    def _calculate_velocity(self, location_events: List[Dict[str, Any]], profile: GeographicProfile) -> float:
        """Calculate location velocity"""
        try:
            if len(location_events) < 2:
                return 0.0
            
            # Get last two locations
            loc1 = location_events[0]
            loc2 = location_events[1]
            
            # Calculate distance (simplified - using country/city as proxy)
            if (loc1['location'].get('country') != loc2['location'].get('country') or
                loc1['location'].get('city') != loc2['location'].get('city')):
                
                # Assume minimum distance between different cities/countries
                distance_km = 100  # Minimum 100km
            else:
                distance_km = 10  # Same city, assume 10km
            
            # Calculate time difference
            time_diff = (loc2['timestamp'] - loc1['timestamp']).total_seconds()
            
            if time_diff <= 0:
                return 0.0
            
            # Calculate velocity (km/hour)
            velocity = (distance_km / time_diff) * 3600
            
            return velocity
            
        except Exception as e:
            logger.error(f"Error calculating velocity: {e}")
            return 0.0
    
    def detect_anomaly(self, user_id: str, ip_address: str, location: Dict[str, Any], 
                       timestamp: datetime) -> Tuple[bool, float]:
        """Detect geographic anomaly"""
        try:
            profile = self.user_profiles.get(user_id)
            
            if not profile:
                return False, 0.0  # New user, no baseline
            
            anomaly_score = 0.0
            reasons = []
            
            # Check if location is typical
            if profile.typical_countries and location.get('country'):
                if location['country'] not in profile.typical_countries:
                    anomaly_score += 0.6
                    reasons.append("Unusual country")
            
            if profile.typical_cities and location.get('city'):
                if location['city'] not in profile.typical_cities:
                    anomaly_score += 0.4
                    reasons.append("Unusual city")
            
            # Check ISP
            if profile.typical_isps and location.get('isp'):
                if location['isp'] not in profile.typical_isps:
                    anomaly_score += 0.3
                    reasons.append("Unusual ISP")
            
            # Check velocity
            if profile.last_location and profile.location_velocity > 0:
                current_velocity = self._calculate_velocity([
                    {'location': profile.last_location['location'], 'timestamp': profile.last_location['timestamp']},
                    {'location': location, 'timestamp': timestamp}
                ], profile)
                
                if current_velocity > self.max_velocity:
                    anomaly_score += 1.0
                    reasons.append("Impossible velocity")
                elif current_velocity > profile.location_velocity * 5:
                    anomaly_score += 0.8
                    reasons.append("Unusual velocity")
            
            # Check for simultaneous locations
            recent_locations = [h for h in profile.location_history 
                              if (timestamp - h['timestamp']).total_seconds() <= 300]  # 5 minutes
            
            if len(recent_locations) > 1:
                # Check if user appears to be in multiple locations simultaneously
                unique_countries = set(h['location'].get('country') for h in recent_locations if h['location'].get('country'))
                if len(unique_countries) > 1:
                    anomaly_score += 0.9
                    reasons.append("Simultaneous locations")
            
            is_anomaly = anomaly_score > 0.7
            
            return is_anomaly, anomaly_score
            
        except Exception as e:
            logger.error(f"Error detecting geographic anomaly: {e}")
            return False, 0.0


class ThreatScoringEngine:
    """Threat scoring evolution engine"""
    
    def __init__(self):
        """Initialize threat scoring engine"""
        self.threat_history: deque = deque(maxlen=10000)
        self.base_weights: Dict[str, float] = {
            'traffic_volume': 0.2,
            'request_pattern': 0.25,
            'authentication_behavior': 0.3,
            'geographic_anomaly': 0.25
        }
        self.adaptive_weights: Dict[str, float] = self.base_weights.copy()
        self.learning_rate: float = 0.1
        self.decay_factor: float = 0.95
        self.min_samples: int = 100
        self.update_interval: int = 3600  # 1 hour
        self.last_update: datetime = datetime.utcnow()
        
        logger.info("Threat scoring engine initialized")
    
    def add_threat_event(self, anomaly_type: AnomalyType, anomaly_score: float, 
                         user_id: Optional[str], timestamp: datetime):
        """Add threat event for learning"""
        try:
            threat_event = {
                'anomaly_type': anomaly_type,
                'anomaly_score': anomaly_score,
                'user_id': user_id,
                'timestamp': timestamp,
                'resolved': False,
                'false_positive': False
            }
            
            self.threat_history.append(threat_event)
            
            # Check if we should update weights
            if len(self.threat_history) >= self.min_samples:
                if (datetime.utcnow() - self.last_update).total_seconds() >= self.update_interval:
                    self._update_weights()
                    
        except Exception as e:
            logger.error(f"Error adding threat event: {e}")
    
    def mark_resolved(self, event_id: str, false_positive: bool = False):
        """Mark threat event as resolved"""
        try:
            for event in self.threat_history:
                if id(event) == int(event_id):
                    event['resolved'] = True
                    event['false_positive'] = false_positive
                    break
            
            # Update weights immediately if we have enough samples
            if len(self.threat_history) >= self.min_samples:
                self._update_weights()
                
        except Exception as e:
            logger.error(f"Error marking event resolved: {e}")
    
    def _update_weights(self):
        """Update adaptive weights based on feedback"""
        try:
            if len(self.threat_history) < self.min_samples:
                return
            
            # Calculate effectiveness for each anomaly type
            type_effectiveness = {}
            
            for anomaly_type in AnomalyType:
                type_events = [e for e in self.threat_history if e['anomaly_type'] == anomaly_type]
                
                if len(type_events) > 0:
                    resolved_events = [e for e in type_events if e['resolved']]
                    false_positives = [e for e in resolved_events if e['false_positive']]
                    
                    if len(resolved_events) > 0:
                        effectiveness = (len(resolved_events) - len(false_positives)) / len(resolved_events)
                        type_effectiveness[anomaly_type.value] = effectiveness
                    else:
                        type_effectiveness[anomaly_type.value] = 0.0
                else:
                    type_effectiveness[anomaly_type.value] = 0.0
            
            # Update weights based on effectiveness
            total_effectiveness = sum(type_effectiveness.values())
            
            if total_effectiveness > 0:
                for anomaly_type, effectiveness in type_effectiveness.items():
                    if anomaly_type in self.base_weights:
                        # Adaptive weight = base_weight * (1 + learning_rate * (effectiveness - avg_effectiveness))
                        avg_effectiveness = total_effectiveness / len(type_effectiveness)
                        adjustment = self.learning_rate * (effectiveness - avg_effectiveness)
                        
                        new_weight = self.base_weights[anomaly_type] * (1 + adjustment)
                        self.adaptive_weights[anomaly_type] = max(0.1, min(1.0, new_weight))
            
            # Normalize weights
            total_weight = sum(self.adaptive_weights.values())
            if total_weight > 0:
                for key in self.adaptive_weights:
                    self.adaptive_weights[key] /= total_weight
            
            self.last_update = datetime.utcnow()
            logger.info(f"Threat weights updated: {self.adaptive_weights}")
            
        except Exception as e:
            logger.error(f"Error updating weights: {e}")
    
    def calculate_threat_score(self, anomaly_type: AnomalyType, anomaly_score: float, 
                              user_id: Optional[str], timestamp: datetime) -> float:
        """Calculate adaptive threat score"""
        try:
            base_score = anomaly_score
            
            # Get adaptive weight for this anomaly type
            weight = self.adaptive_weights.get(anomaly_type.value, self.base_weights.get(anomaly_type.value, 0.25))
            
            # Check user history
            if user_id:
                user_events = [e for e in self.threat_history if e['user_id'] == user_id]
                user_false_positives = [e for e in user_events if e['false_positive']]
                
                if len(user_events) > 0:
                    false_positive_rate = len(user_false_positives) / len(user_events)
                    # Reduce score if user has high false positive rate
                    base_score *= (1 - false_positive_rate * 0.5)
            
            # Apply time decay for older patterns
            recent_events = [e for e in self.threat_history 
                           if (timestamp - e['timestamp']).total_seconds() <= 86400]  # 24 hours
            
            if len(recent_events) > 0:
                time_factor = len(recent_events) / max(len(self.threat_history), 1)
                base_score *= (1 + time_factor * 0.2)  # Increase score if recent activity
            
            # Calculate final threat score
            threat_score = base_score * weight
            
            return min(1.0, max(0.0, threat_score))
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return 0.0


class AdaptiveAlertSeverity:
    """Adaptive alert severity system"""
    
    def __init__(self):
        """Initialize adaptive alert severity system"""
        self.alert_history: deque = deque(maxlen=10000)
        self.severity_thresholds: Dict[AlertSeverity, float] = {
            AlertSeverity.LOW: 0.3,
            AlertSeverity.MEDIUM: 0.5,
            AlertSeverity.HIGH: 0.7,
            AlertSeverity.CRITICAL: 0.9
        }
        self.adaptive_thresholds: Dict[AlertSeverity, float] = self.severity_thresholds.copy()
        self.adjustment_rate: float = 0.1
        self.min_alerts_per_hour: int = 10
        self.update_interval: int = 1800  # 30 minutes
        self.last_update: datetime = datetime.utcnow()
        
        logger.info("Adaptive alert severity system initialized")
    
    def add_alert(self, severity: AlertSeverity, threat_score: float, 
                  timestamp: datetime, resolved: bool = False, false_positive: bool = False):
        """Add alert for learning"""
        try:
            alert = {
                'severity': severity,
                'threat_score': threat_score,
                'timestamp': timestamp,
                'resolved': resolved,
                'false_positive': false_positive
            }
            
            self.alert_history.append(alert)
            
            # Check if we should update thresholds
            if len(self.alert_history) >= self.min_alerts_per_hour:
                if (datetime.utcnow() - self.last_update).total_seconds() >= self.update_interval:
                    self._update_thresholds()
                    
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
    
    def _update_thresholds(self):
        """Update adaptive thresholds based on alert performance"""
        try:
            if len(self.alert_history) < self.min_alerts_per_hour:
                return
            
            # Calculate false positive rates for each severity
            severity_performance = {}
            
            for severity in AlertSeverity:
                severity_alerts = [a for a in self.alert_history if a['severity'] == severity]
                
                if len(severity_alerts) > 0:
                    resolved_alerts = [a for a in severity_alerts if a['resolved']]
                    false_positives = [a for a in resolved_alerts if a['false_positive']]
                    
                    if len(resolved_alerts) > 0:
                        false_positive_rate = len(false_positives) / len(resolved_alerts)
                        avg_threat_score = statistics.mean([a['threat_score'] for a in severity_alerts])
                        
                        severity_performance[severity.value] = {
                            'false_positive_rate': false_positive_rate,
                            'avg_threat_score': avg_threat_score,
                            'total_alerts': len(severity_alerts)
                        }
                    else:
                        severity_performance[severity.value] = {
                            'false_positive_rate': 0.0,
                            'avg_threat_score': 0.0,
                            'total_alerts': len(severity_alerts)
                        }
            
            # Update thresholds based on performance
            for severity, performance in severity_performance.items():
                severity_enum = AlertSeverity(severity)
                current_threshold = self.adaptive_thresholds[severity_enum]
                
                # If high false positive rate, increase threshold
                if performance['false_positive_rate'] > 0.3:
                    new_threshold = current_threshold + self.adjustment_rate
                # If low false positive rate and high threat scores, decrease threshold
                elif performance['false_positive_rate'] < 0.1 and performance['avg_threat_score'] > 0.7:
                    new_threshold = current_threshold - self.adjustment_rate
                else:
                    new_threshold = current_threshold
                
                # Ensure threshold stays within bounds
                if severity_enum == AlertSeverity.LOW:
                    new_threshold = max(0.1, min(0.4, new_threshold))
                elif severity_enum == AlertSeverity.MEDIUM:
                    new_threshold = max(0.3, min(0.6, new_threshold))
                elif severity_enum == AlertSeverity.HIGH:
                    new_threshold = max(0.5, min(0.8, new_threshold))
                elif severity_enum == AlertSeverity.CRITICAL:
                    new_threshold = max(0.7, min(1.0, new_threshold))
                
                self.adaptive_thresholds[severity_enum] = new_threshold
            
            self.last_update = datetime.utcnow()
            logger.info(f"Adaptive thresholds updated: {self.adaptive_thresholds}")
            
        except Exception as e:
            logger.error(f"Error updating thresholds: {e}")
    
    def determine_severity(self, threat_score: float, anomaly_type: AnomalyType) -> AlertSeverity:
        """Determine adaptive alert severity"""
        try:
            # Start with base severity based on threat score
            if threat_score >= self.adaptive_thresholds[AlertSeverity.CRITICAL]:
                base_severity = AlertSeverity.CRITICAL
            elif threat_score >= self.adaptive_thresholds[AlertSeverity.HIGH]:
                base_severity = AlertSeverity.HIGH
            elif threat_score >= self.adaptive_thresholds[AlertSeverity.MEDIUM]:
                base_severity = AlertSeverity.MEDIUM
            else:
                base_severity = AlertSeverity.LOW
            
            # Adjust based on anomaly type
            type_adjustments = {
                AnomalyType.AUTHENTICATION_BEHAVIOR: 1,
                AnomalyType.GEOGRAPHIC_ANOMALY: 0.8,
                AnomalyType.REQUEST_PATTERN: 0.6,
                AnomalyType.TRAFFIC_VOLUME: 0.4,
                AnomalyType.TIME_PATTERN: 0.3,
                AnomalyType.USER_BEHAVIOR: 0.7,
                AnomalyType.SYSTEM_BEHAVIOR: 0.5
            }
            
            adjustment = type_adjustments.get(anomaly_type, 1.0)
            adjusted_score = threat_score * adjustment
            
            # Re-determine severity with adjusted score
            if adjusted_score >= self.adaptive_thresholds[AlertSeverity.CRITICAL]:
                return AlertSeverity.CRITICAL
            elif adjusted_score >= self.adaptive_thresholds[AlertSeverity.HIGH]:
                return AlertSeverity.HIGH
            elif adjusted_score >= self.adaptive_thresholds[AlertSeverity.MEDIUM]:
                return AlertSeverity.MEDIUM
            else:
                return AlertSeverity.LOW
                
        except Exception as e:
            logger.error(f"Error determining severity: {e}")
            return AlertSeverity.MEDIUM


class BehavioralAnomalyEngine:
    """Main behavioral anomaly engine coordinator"""
    
    def __init__(self):
        """Initialize behavioral anomaly engine"""
        self.traffic_learner = BaselineTrafficLearner()
        self.pattern_detector = RequestPatternDetector()
        self.auth_detector = AuthenticationBehaviorDetector()
        self.geo_detector = GeographicAnomalyDetector()
        self.threat_scorer = ThreatScoringEngine()
        self.alert_severity = AdaptiveAlertSeverity()
        
        self.anomaly_events: List[AnomalyEvent] = []
        self.monitoring_task: Optional[asyncio.Task] = None
        
        logger.info("Behavioral anomaly engine initialized")
    
    async def start(self):
        """Start the behavioral anomaly engine"""
        logger.info("Starting behavioral anomaly engine")
        
        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("Behavioral anomaly engine started")
    
    async def stop(self):
        """Stop the behavioral anomaly engine"""
        logger.info("Stopping behavioral anomaly engine")
        
        # Cancel monitoring task
        if self.monitoring_task:
            self.monitoring_task.cancel()
        
        logger.info("Behavioral anomaly engine stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                # Clean up old events
                await self._cleanup_old_events()
                
                # Wait for next iteration
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_old_events(self):
        """Clean up old anomaly events"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=30)
            self.anomaly_events = [event for event in self.anomaly_events if event.timestamp > cutoff_time]
        except Exception as e:
            logger.error(f"Error cleaning up old events: {e}")
    
    async def process_request(self, endpoint: str, method: str, response_time: float, 
                           payload_size: float, user_agent: str, status_code: int, 
                           user_id: Optional[str], ip_address: str, 
                           location: Optional[Dict[str, Any]], timestamp: datetime):
        """Process request for anomaly detection"""
        try:
            anomalies = []
            
            # Traffic volume anomaly detection
            requests_per_minute = await self._get_requests_per_minute(timestamp)
            is_traffic_anomaly, traffic_score = self.traffic_learner.is_anomalous_traffic(
                requests_per_minute, response_time, payload_size, timestamp
            )
            
            if is_traffic_anomaly:
                anomalies.append((AnomalyType.TRAFFIC_VOLUME, traffic_score))
            
            # Request pattern anomaly detection
            is_pattern_anomaly, pattern_score = self.pattern_detector.detect_anomaly(
                endpoint, method, response_time, payload_size, user_agent, status_code, timestamp
            )
            
            if is_pattern_anomaly:
                anomalies.append((AnomalyType.REQUEST_PATTERN, pattern_score))
            
            # Geographic anomaly detection
            if location:
                is_geo_anomaly, geo_score = self.geo_detector.detect_anomaly(
                    user_id, ip_address, location, timestamp
                )
                
                if is_geo_anomaly:
                    anomalies.append((AnomalyType.GEOGRAPHIC_ANOMALY, geo_score))
            
            # Process anomalies
            for anomaly_type, anomaly_score in anomalies:
                await self._process_anomaly(
                    anomaly_type, anomaly_score, user_id, ip_address, endpoint, timestamp
                )
            
        except Exception as e:
            logger.error(f"Error processing request: {e}")
    
    async def process_authentication(self, user_id: str, success: bool, ip_address: str, 
                                   user_agent: str, location: Optional[Dict[str, Any]], 
                                   timestamp: datetime):
        """Process authentication for anomaly detection"""
        try:
            # Authentication behavior anomaly detection
            is_auth_anomaly, auth_score = self.auth_detector.detect_anomaly(
                user_id, success, ip_address, user_agent, location or {}, timestamp
            )
            
            if is_auth_anomaly:
                await self._process_anomaly(
                    AnomalyType.AUTHENTICATION_BEHAVIOR, auth_score, user_id, ip_address, 
                    "authentication", timestamp
                )
            
        except Exception as e:
            logger.error(f"Error processing authentication: {e}")
    
    async def _get_requests_per_minute(self, timestamp: datetime) -> float:
        """Get requests per minute for traffic analysis"""
        try:
            # This would typically come from request metrics
            # For now, we'll simulate it
            import random
            base_rpm = 100
            noise = random.uniform(-20, 20)
            
            # Add time-based variation
            hour_factor = 1.0
            if 9 <= timestamp.hour <= 17:  # Business hours
                hour_factor = 1.5
            elif 22 <= timestamp.hour <= 6:  # Night hours
                hour_factor = 0.5
            
            return max(0, base_rpm * hour_factor + noise)
            
        except Exception as e:
            logger.error(f"Error getting requests per minute: {e}")
            return 0.0
    
    async def _process_anomaly(self, anomaly_type: AnomalyType, anomaly_score: float, 
                             user_id: Optional[str], ip_address: Optional[str], 
                             endpoint: Optional[str], timestamp: datetime):
        """Process detected anomaly"""
        try:
            # Calculate threat score
            threat_score = self.threat_scorer.calculate_threat_score(
                anomaly_type, anomaly_score, user_id, timestamp
            )
            
            # Determine alert severity
            severity = self.alert_severity.determine_severity(threat_score, anomaly_type)
            
            # Determine threat level
            if threat_score >= 0.8:
                threat_level = ThreatLevel.CRITICAL
            elif threat_score >= 0.6:
                threat_level = ThreatLevel.HIGH
            elif threat_score >= 0.4:
                threat_level = ThreatLevel.ELEVATED
            elif threat_score >= 0.2:
                threat_level = ThreatLevel.MODERATE
            else:
                threat_level = ThreatLevel.LOW
            
            # Create anomaly event
            event = AnomalyEvent(
                event_id=f"anomaly_{int(time.time())}_{len(self.anomaly_events)}",
                anomaly_type=anomaly_type,
                severity=severity,
                threat_level=threat_level,
                confidence=anomaly_score,
                timestamp=timestamp,
                user_id=user_id,
                ip_address=ip_address,
                endpoint=endpoint,
                details={
                    'detection_method': 'behavioral_analysis',
                    'baseline_available': True
                },
                baseline_metrics={},
                current_metrics={
                    'anomaly_score': anomaly_score,
                    'threat_score': threat_score
                },
                deviation_score=anomaly_score,
                adaptive_severity=severity,
                threat_score=threat_score,
                false_positive_probability=1.0 - threat_score
            )
            
            self.anomaly_events.append(event)
            
            # Add to threat scoring engine for learning
            self.threat_scorer.add_threat_event(anomaly_type, anomaly_score, user_id, timestamp)
            
            # Add to alert severity system for learning
            self.alert_severity.add_alert(severity, threat_score, timestamp)
            
            logger.warning(f"Behavioral anomaly detected: {anomaly_type.value} - Score: {anomaly_score:.2f}, Threat: {threat_score:.2f}, Severity: {severity.value}")
            
        except Exception as e:
            logger.error(f"Error processing anomaly: {e}")
    
    async def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get anomaly summary"""
        try:
            if not self.anomaly_events:
                return {
                    'total_anomalies': 0,
                    'by_type': {},
                    'by_severity': {},
                    'by_threat_level': {},
                    'recent_anomalies': []
                }
            
            # Count anomalies by type
            by_type = Counter([event.anomaly_type.value for event in self.anomaly_events])
            
            # Count anomalies by severity
            by_severity = Counter([event.severity.value for event in self.anomaly_events])
            
            # Count anomalies by threat level
            by_threat_level = Counter([event.threat_level.value for event in self.anomaly_events])
            
            # Get recent anomalies
            recent_anomalies = sorted(self.anomaly_events, key=lambda x: x.timestamp, reverse=True)[:10]
            
            return {
                'total_anomalies': len(self.anomaly_events),
                'by_type': dict(by_type),
                'by_severity': dict(by_severity),
                'by_threat_level': dict(by_threat_level),
                'recent_anomalies': [
                    {
                        'event_id': event.event_id,
                        'type': event.anomaly_type.value,
                        'severity': event.severity.value,
                        'threat_level': event.threat_level.value,
                        'confidence': event.confidence,
                        'timestamp': event.timestamp.isoformat(),
                        'user_id': event.user_id,
                        'threat_score': event.threat_score
                    }
                    for event in recent_anomalies
                ]
            }
            
        except Exception as e:
            logger.error(f"Error getting anomaly summary: {e}")
            return {'error': str(e)}


# Global behavioral anomaly engine instance
behavioral_anomaly_engine = BehavioralAnomalyEngine()


# API functions
async def initialize_behavioral_anomaly_engine() -> str:
    """Initialize behavioral anomaly engine"""
    try:
        await behavioral_anomaly_engine.start()
        logger.info("Behavioral anomaly engine initialized")
        return "Behavioral anomaly engine initialized"
    except Exception as e:
        logger.error(f"Error initializing behavioral anomaly engine: {e}")
        return f"Error initializing behavioral anomaly engine: {e}"


async def stop_behavioral_anomaly_engine() -> str:
    """Stop behavioral anomaly engine"""
    try:
        await behavioral_anomaly_engine.stop()
        logger.info("Behavioral anomaly engine stopped")
        return "Behavioral anomaly engine stopped"
    except Exception as e:
        logger.error(f"Error stopping behavioral anomaly engine: {e}")
        return f"Error stopping behavioral anomaly engine: {e}"


async def process_behavioral_request(endpoint: str, method: str, response_time: float, 
                                   payload_size: float, user_agent: str, status_code: int, 
                                   user_id: Optional[str], ip_address: str, 
                                   location: Optional[Dict[str, Any]]) -> str:
    """Process behavioral request for anomaly detection"""
    try:
        await behavioral_anomaly_engine.process_request(
            endpoint, method, response_time, payload_size, user_agent, status_code,
            user_id, ip_address, location, datetime.utcnow()
        )
        return "Behavioral request processed"
    except Exception as e:
        logger.error(f"Error processing behavioral request: {e}")
        return f"Error processing behavioral request: {e}"


async def process_behavioral_authentication(user_id: str, success: bool, ip_address: str, 
                                          user_agent: str, location: Optional[Dict[str, Any]]) -> str:
    """Process behavioral authentication for anomaly detection"""
    try:
        await behavioral_anomaly_engine.process_authentication(
            user_id, success, ip_address, user_agent, location, datetime.utcnow()
        )
        return "Behavioral authentication processed"
    except Exception as e:
        logger.error(f"Error processing behavioral authentication: {e}")
        return f"Error processing behavioral authentication: {e}"


async def get_behavioral_anomaly_summary() -> Dict[str, Any]:
    """Get behavioral anomaly summary"""
    try:
        return await behavioral_anomaly_engine.get_anomaly_summary()
    except Exception as e:
        logger.error(f"Error getting anomaly summary: {e}")
        return {'error': str(e)}


async def get_traffic_baseline() -> Optional[Dict[str, Any]]:
    """Get traffic baseline"""
    try:
        baseline = behavioral_anomaly_engine.traffic_learner.get_baseline()
        if baseline:
            return {
                'avg_requests_per_minute': baseline.avg_requests_per_minute,
                'std_requests_per_minute': baseline.std_requests_per_minute,
                'avg_response_time': baseline.avg_response_time,
                'std_response_time': baseline.std_response_time,
                'peak_hours': baseline.peak_hours,
                'low_hours': baseline.low_hours,
                'created_at': baseline.created_at.isoformat(),
                'updated_at': baseline.updated_at.isoformat()
            }
        return None
    except Exception as e:
        logger.error(f"Error getting traffic baseline: {e}")
        return None


async def get_threat_scoring_status() -> Dict[str, Any]:
    """Get threat scoring status"""
    try:
        return {
            'adaptive_weights': behavioral_anomaly_engine.threat_scorer.adaptive_weights,
            'base_weights': behavioral_anomaly_engine.threat_scorer.base_weights,
            'total_events': len(behavioral_anomaly_engine.threat_scorer.threat_history),
            'last_update': behavioral_anomaly_engine.threat_scorer.last_update.isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting threat scoring status: {e}")
        return {'error': str(e)}


async def get_adaptive_severity_status() -> Dict[str, Any]:
    """Get adaptive severity status"""
    try:
        return {
            'adaptive_thresholds': {k.value: v for k, v in behavioral_anomaly_engine.alert_severity.adaptive_thresholds.items()},
            'base_thresholds': {k.value: v for k, v in behavioral_anomaly_engine.alert_severity.severity_thresholds.items()},
            'total_alerts': len(behavioral_anomaly_engine.alert_severity.alert_history),
            'last_update': behavioral_anomaly_engine.alert_severity.last_update.isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting adaptive severity status: {e}")
        return {'error': str(e)}
