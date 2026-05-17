#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Host Monitor
Comprehensive host system monitoring and integration
"""

import os
import sys
import asyncio
import logging
import json
import time
import uuid
import psutil
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from collections import defaultdict, deque
from enum import Enum

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import monitoring components
from windows_guardian.windows_guardian import windows_guardian, SecurityEvent, AlertType, ThreatLevel
from process_watchers.process_analyzer import process_analyzer, ProcessThreat
from event_watchers.event_monitor import event_monitor, SecurityAlert

logger = logging.getLogger(__name__)


class MonitoringStatus(Enum):
    """Monitoring status enumeration"""
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


class HostHealthStatus(Enum):
    """Host health status enumeration"""
    HEALTHY = "healthy"
    WARNING = "warning"
    DEGRADED = "degraded"
    CRITICAL = "critical"


@dataclass
class HostMetrics:
    """Host system metrics"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: Dict[str, int]
    process_count: int
    connection_count: int
    active_threats: int
    security_events: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'disk_usage': self.disk_usage,
            'network_io': self.network_io,
            'process_count': self.process_count,
            'connection_count': self.connection_count,
            'active_threats': self.active_threats,
            'security_events': self.security_events
        }


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    threat_id: str
    timestamp: datetime
    threat_type: str
    severity: ThreatLevel
    confidence: float
    source: str
    indicators: Dict[str, Any]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'threat_id': self.threat_id,
            'timestamp': self.timestamp.isoformat(),
            'threat_type': self.threat_type,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'source': self.source,
            'indicators': self.indicators,
            'recommendations': self.recommendations
        }


class HostMonitor:
    """Comprehensive host monitoring system"""
    
    def __init__(self):
        """Initialize host monitor"""
        self.status = MonitoringStatus.STOPPED
        self.metrics_history: deque = deque(maxlen=1000)
        self.threat_intelligence: deque = deque(maxlen=500)
        self.alert_callbacks: List[Callable] = []
        
        # Monitoring components
        self.windows_guardian = windows_guardian
        self.process_analyzer = process_analyzer
        self.event_monitor = event_monitor
        
        # Configuration
        self.config = {
            'metrics_interval': 30,  # seconds
            'health_check_interval': 60,  # seconds
            'threat_analysis_interval': 120,  # seconds
            'max_metrics_history': 1000,
            'auto_quarantine': False,
            'alert_threshold': 0.7,
            'enable_real_time_alerts': True
        }
        
        # Host information
        self.host_info = self._get_host_info()
        
        # Statistics
        self.stats = {
            'start_time': None,
            'total_alerts': 0,
            'threats_detected': 0,
            'processes_analyzed': 0,
            'events_processed': 0,
            'uptime': 0
        }
        
        logger.info("Host monitor initialized")
    
    def _get_host_info(self) -> Dict[str, Any]:
        """Get host system information"""
        try:
            return {
                'hostname': socket.gethostname(),
                'platform': sys.platform,
                'architecture': os.name,
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_total': psutil.disk_usage('/').total if os.name != 'nt' else psutil.disk_usage('C:\\').total,
                'network_interfaces': list(psutil.net_if_addrs().keys()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting host info: {e}")
            return {}
    
    async def start(self):
        """Start host monitoring"""
        try:
            logger.info("Starting host monitor")
            
            self.status = MonitoringStatus.ACTIVE
            self.stats['start_time'] = datetime.utcnow()
            
            # Start monitoring components
            await self.windows_guardian.start()
            await self.event_monitor.start()
            
            # Setup alert callbacks
            self._setup_alert_callbacks()
            
            # Start monitoring tasks
            asyncio.create_task(self._collect_metrics())
            asyncio.create_task(self._health_check_loop())
            asyncio.create_task(self._threat_analysis_loop())
            
            logger.info("Host monitor started successfully")
            
        except Exception as e:
            logger.error(f"Error starting host monitor: {e}")
            self.status = MonitoringStatus.ERROR
            raise
    
    async def stop(self):
        """Stop host monitoring"""
        try:
            logger.info("Stopping host monitor")
            
            self.status = MonitoringStatus.STOPPED
            
            # Stop monitoring components
            await self.windows_guardian.stop()
            await self.event_monitor.stop()
            
            logger.info("Host monitor stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping host monitor: {e}")
    
    def _setup_alert_callbacks(self):
        """Setup alert callbacks"""
        # Windows Guardian callback
        async def guardian_callback(event: SecurityEvent):
            await self._handle_guardian_alert(event)
        
        self.windows_guardian.add_alert_callback(guardian_callback)
        
        # Event Monitor callback
        async def event_callback(event):
            await self._handle_event_alert(event)
        
        self.event_monitor.add_event_callback(event_callback)
    
    async def _handle_guardian_alert(self, event: SecurityEvent):
        """Handle Windows Guardian alert"""
        try:
            # Update statistics
            self.stats['threats_detected'] += 1
            self.stats['total_alerts'] += 1
            
            # Create threat intelligence
            threat_intel = ThreatIntelligence(
                threat_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                threat_type=event.event_type.value,
                severity=event.threat_level,
                confidence=0.8,
                source='Windows Guardian',
                indicators={
                    'process_id': event.process_id,
                    'user': event.user,
                    'file_path': event.file_path,
                    'details': event.details
                },
                recommendations=self._generate_recommendations(event)
            )
            
            self.threat_intelligence.append(threat_intel)
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    await callback({
                        'type': 'guardian_alert',
                        'event': event.to_dict(),
                        'threat_intel': threat_intel.to_dict()
                    })
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            logger.warning(f"Guardian alert: {event.description}")
            
        except Exception as e:
            logger.error(f"Error handling guardian alert: {e}")
    
    async def _handle_event_alert(self, event):
        """Handle event monitor alert"""
        try:
            # Update statistics
            self.stats['events_processed'] += 1
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    await callback({
                        'type': 'event_alert',
                        'event': event.to_dict()
                    })
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
        except Exception as e:
            logger.error(f"Error handling event alert: {e}")
    
    def _generate_recommendations(self, event: SecurityEvent) -> List[str]:
        """Generate recommendations for security event"""
        recommendations = []
        
        try:
            if event.event_type == AlertType.PROCESS_SUSPICIOUS:
                recommendations.extend([
                    "Investigate the suspicious process",
                    "Check process parent and child relationships",
                    "Review process network connections",
                    "Consider quarantining if confirmed malicious"
                ])
            
            elif event.event_type == AlertType.PROCESS_POWERSHELL:
                recommendations.extend([
                    "Review PowerShell command for malicious intent",
                    "Check if command is authorized",
                    "Monitor for lateral movement",
                    "Review user account security"
                ])
            
            elif event.event_type == AlertType.PROCESS_UNSIGNED:
                recommendations.extend([
                    "Verify the legitimacy of the unsigned binary",
                    "Check file hash against threat intelligence",
                    "Consider blocking the executable",
                    "Review digital signature policies"
                ])
            
            elif event.event_type == AlertType.FILE_RANSOMWARE:
                recommendations.extend([
                    "IMMEDIATE: Isolate affected system",
                    "Stop the ransomware process",
                    "Restore from backup if available",
                    "Review network connections for lateral movement"
                ])
            
            elif event.event_type == AlertType.NETWORK_SUSPICIOUS:
                recommendations.extend([
                    "Investigate the network connection",
                    "Block the remote IP if malicious",
                    "Review firewall rules",
                    "Monitor for data exfiltration"
                ])
            
            else:
                recommendations.extend([
                    "Investigate the security event",
                    "Review system logs for related activity",
                    "Monitor for additional suspicious behavior",
                    "Document findings for incident response"
                ])
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
        
        return recommendations
    
    async def _collect_metrics(self):
        """Collect system metrics"""
        try:
            while self.status == MonitoringStatus.ACTIVE:
                try:
                    # Collect system metrics
                    cpu_usage = psutil.cpu_percent(interval=1)
                    memory = psutil.virtual_memory()
                    disk = psutil.disk_usage('/') if os.name != 'nt' else psutil.disk_usage('C:\\')
                    
                    # Network I/O
                    net_io = psutil.net_io_counters()
                    network_io = {
                        'bytes_sent': net_io.bytes_sent,
                        'bytes_recv': net_io.bytes_recv,
                        'packets_sent': net_io.packets_sent,
                        'packets_recv': net_io.packets_recv
                    }
                    
                    # Process and connection counts
                    process_count = len(psutil.pids())
                    connection_count = len(psutil.net_connections())
                    
                    # Get threat and event counts
                    guardian_stats = self.windows_guardian.get_statistics()
                    active_threats = guardian_stats.get('threats_detected', 0)
                    security_events = len(self.event_monitor.events)
                    
                    # Create metrics
                    metrics = HostMetrics(
                        timestamp=datetime.utcnow(),
                        cpu_usage=cpu_usage,
                        memory_usage=memory.percent,
                        disk_usage=disk.percent,
                        network_io=network_io,
                        process_count=process_count,
                        connection_count=connection_count,
                        active_threats=active_threats,
                        security_events=security_events
                    )
                    
                    # Store metrics
                    self.metrics_history.append(metrics)
                    
                    # Update uptime
                    if self.stats['start_time']:
                        self.stats['uptime'] = (datetime.utcnow() - self.stats['start_time']).total_seconds()
                    
                    await asyncio.sleep(self.config['metrics_interval'])
                    
                except Exception as e:
                    logger.error(f"Error collecting metrics: {e}")
                    await asyncio.sleep(10)
                    
        except Exception as e:
            logger.error(f"Metrics collection error: {e}")
    
    async def _health_check_loop(self):
        """Health check loop"""
        try:
            while self.status == MonitoringStatus.ACTIVE:
                try:
                    health_status = await self._assess_host_health()
                    
                    # Notify if health is degraded
                    if health_status in [HostHealthStatus.WARNING, HostHealthStatus.DEGRADED, HostHealthStatus.CRITICAL]:
                        for callback in self.alert_callbacks:
                            try:
                                await callback({
                                    'type': 'health_alert',
                                    'status': health_status.value,
                                    'timestamp': datetime.utcnow().isoformat()
                                })
                            except Exception as e:
                                logger.error(f"Error in health alert callback: {e}")
                    
                    await asyncio.sleep(self.config['health_check_interval'])
                    
                except Exception as e:
                    logger.error(f"Error in health check: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            logger.error(f"Health check loop error: {e}")
    
    async def _assess_host_health(self) -> HostHealthStatus:
        """Assess host health status"""
        try:
            if not self.metrics_history:
                return HostHealthStatus.HEALTHY
            
            # Get latest metrics
            latest_metrics = self.metrics_history[-1]
            
            # Check CPU usage
            if latest_metrics.cpu_usage > 90:
                return HostHealthStatus.CRITICAL
            elif latest_metrics.cpu_usage > 80:
                return HostHealthStatus.WARNING
            
            # Check memory usage
            if latest_metrics.memory_usage > 95:
                return HostHealthStatus.CRITICAL
            elif latest_metrics.memory_usage > 85:
                return HostHealthStatus.WARNING
            
            # Check disk usage
            if latest_metrics.disk_usage > 95:
                return HostHealthStatus.CRITICAL
            elif latest_metrics.disk_usage > 90:
                return HostHealthStatus.WARNING
            
            # Check active threats
            if latest_metrics.active_threats > 10:
                return HostHealthStatus.CRITICAL
            elif latest_metrics.active_threats > 5:
                return HostHealthStatus.WARNING
            
            # Check security events
            if latest_metrics.security_events > 100:
                return HostHealthStatus.WARNING
            
            return HostHealthStatus.HEALTHY
            
        except Exception as e:
            logger.error(f"Error assessing host health: {e}")
            return HostHealthStatus.ERROR
    
    async def _threat_analysis_loop(self):
        """Threat analysis loop"""
        try:
            while self.status == MonitoringStatus.ACTIVE:
                try:
                    await self._analyze_threat_patterns()
                    await asyncio.sleep(self.config['threat_analysis_interval'])
                    
                except Exception as e:
                    logger.error(f"Error in threat analysis: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            logger.error(f"Threat analysis loop error: {e}")
    
    async def _analyze_threat_patterns(self):
        """Analyze threat patterns"""
        try:
            # Get recent threats
            recent_threats = list(self.threat_intelligence)[-50:]  # Last 50 threats
            
            if len(recent_threats) < 5:
                return
            
            # Analyze threat patterns
            threat_types = defaultdict(int)
            severity_counts = defaultdict(int)
            
            for threat in recent_threats:
                threat_types[threat.threat_type] += 1
                severity_counts[threat.severity.value] += 1
            
            # Check for patterns
            for threat_type, count in threat_types.items():
                if count >= 10:  # Threshold for pattern detection
                    await self._create_pattern_alert(threat_type, count, recent_threats)
            
        except Exception as e:
            logger.error(f"Error analyzing threat patterns: {e}")
    
    async def _create_pattern_alert(self, threat_type: str, count: int, threats: List[ThreatIntelligence]):
        """Create pattern alert"""
        try:
            alert = {
                'type': 'pattern_alert',
                'threat_type': threat_type,
                'count': count,
                'time_window': 'Recent',
                'severity': 'high',
                'timestamp': datetime.utcnow().isoformat(),
                'recommendations': [
                    f"Investigate recurring {threat_type} threats",
                    "Review security controls",
                    "Consider implementing additional protections",
                    "Monitor for escalation"
                ]
            }
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    await callback(alert)
                except Exception as e:
                    logger.error(f"Error in pattern alert callback: {e}")
            
            logger.warning(f"Pattern alert: {count} instances of {threat_type}")
            
        except Exception as e:
            logger.error(f"Error creating pattern alert: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Add alert callback"""
        self.alert_callbacks.append(callback)
    
    def get_host_info(self) -> Dict[str, Any]:
        """Get host information"""
        return self.host_info.copy()
    
    def get_metrics(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system metrics"""
        try:
            metrics = list(self.metrics_history)[-limit:]
            return [metric.to_dict() for metric in metrics]
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return []
    
    def get_threat_intelligence(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get threat intelligence"""
        try:
            threats = list(self.threat_intelligence)[-limit:]
            return [threat.to_dict() for threat in threats]
        except Exception as e:
            logger.error(f"Error getting threat intelligence: {e}")
            return []
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        try:
            # Get latest metrics
            latest_metrics = self.metrics_history[-1] if self.metrics_history else None
            
            # Get recent threats
            recent_threats = list(self.threat_intelligence)[-10:]
            
            # Get recent events
            recent_events = self.event_monitor.get_events(limit=20)
            
            # Get health status
            health_status = self._assess_host_health().value
            
            return {
                'host_info': self.host_info,
                'status': self.status.value,
                'health_status': health_status,
                'latest_metrics': latest_metrics.to_dict() if latest_metrics else None,
                'recent_threats': [threat.to_dict() for threat in recent_threats],
                'recent_events': recent_events,
                'statistics': self.stats,
                'guardian_stats': self.windows_guardian.get_statistics(),
                'event_stats': self.event_monitor.get_statistics(),
                'process_stats': self.process_analyzer.get_statistics()
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {'error': str(e)}
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        try:
            uptime = (datetime.utcnow() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0
            
            return {
                'status': self.status.value,
                'uptime': uptime,
                'host_info': self.host_info,
                'statistics': self.stats,
                'config': self.config,
                'components': {
                    'windows_guardian': self.windows_guardian.get_statistics(),
                    'event_monitor': self.event_monitor.get_statistics(),
                    'process_analyzer': self.process_analyzer.get_statistics()
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {'error': str(e)}


# Global host monitor instance
host_monitor = HostMonitor()


# API functions
async def start_host_monitor() -> str:
    """Start host monitor"""
    try:
        await host_monitor.start()
        logger.info("Host monitor started")
        return "Host monitor started successfully"
    except Exception as e:
        logger.error(f"Error starting host monitor: {e}")
        return f"Error starting host monitor: {e}"


async def stop_host_monitor() -> str:
    """Stop host monitor"""
    try:
        await host_monitor.stop()
        logger.info("Host monitor stopped")
        return "Host monitor stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping host monitor: {e}")
        return f"Error stopping host monitor: {e}"


def get_host_info() -> Dict[str, Any]:
    """Get host information"""
    try:
        return host_monitor.get_host_info()
    except Exception as e:
        logger.error(f"Error getting host info: {e}")
        return {'error': str(e)}


def get_host_metrics(limit: int = 100) -> List[Dict[str, Any]]:
    """Get host metrics"""
    try:
        return host_monitor.get_metrics(limit)
    except Exception as e:
        logger.error(f"Error getting host metrics: {e}")
        return []


def get_threat_intelligence(limit: int = 100) -> List[Dict[str, Any]]:
    """Get threat intelligence"""
    try:
        return host_monitor.get_threat_intelligence(limit)
    except Exception as e:
        logger.error(f"Error getting threat intelligence: {e}")
        return []


def get_dashboard_data() -> Dict[str, Any]:
    """Get dashboard data"""
    try:
        return host_monitor.get_dashboard_data()
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return {'error': str(e)}


def get_monitor_status() -> Dict[str, Any]:
    """Get monitor status"""
    try:
        return host_monitor.get_status()
    except Exception as e:
        logger.error(f"Error getting monitor status: {e}")
        return {'error': str(e)}


def add_monitor_alert_callback(callback: Callable):
    """Add monitor alert callback"""
    try:
        host_monitor.add_alert_callback(callback)
        logger.info("Monitor alert callback added")
    except Exception as e:
        logger.error(f"Error adding monitor alert callback: {e}"


# Initialize host monitor
async def initialize_host_monitor() -> str:
    """Initialize host monitor"""
    try:
        await start_host_monitor()
        logger.info("Host monitor initialized")
        return "Host monitor initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing host monitor: {e}")
        return f"Error initializing host monitor: {e}"


# Cleanup function
async def cleanup_host_monitor() -> str:
    """Cleanup host monitor"""
    try:
        await stop_host_monitor()
        logger.info("Host monitor cleaned up")
        return "Host monitor cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up host monitor: {e}")
        return f"Error cleaning up host monitor: {e}"
