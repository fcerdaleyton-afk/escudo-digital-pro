#!/usr/bin/env python3
"""
MARY V5 SHIELD CORE v5.0 Enterprise - Alert Manager
Comprehensive alerting system with SMTP and WebSocket support
"""

import os
import sys
import asyncio
import logging
import smtplib
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from enum import Enum

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
def setup_logging():
    """Setup logging with proper path handling"""
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, 'alert_manager.log')),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity enumeration"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status enumeration"""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    ACKNOWLEDGED = "acknowledged"


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    title: str
    message: str
    source: str
    details: Dict[str, Any]
    status: AlertStatus = AlertStatus.PENDING
    recipients: List[str] = None
    delivery_attempts: int = 0
    last_attempt: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'title': self.title,
            'message': self.message,
            'source': self.source,
            'details': self.details,
            'status': self.status.value,
            'recipients': self.recipients or [],
            'delivery_attempts': self.delivery_attempts,
            'last_attempt': self.last_attempt.isoformat() if self.last_attempt else None
        }


class AlertManager:
    """Comprehensive alert management system"""
    
    def __init__(self):
        """Initialize alert manager"""
        self.alerts: Dict[str, Alert] = {}
        self.alert_queue: asyncio.Queue = asyncio.Queue()
        self.websocket_clients: List[Callable] = []
        self.smtp_config = self._get_smtp_config()
        self.is_running = False
        
        # Configuration
        self.config = {
            'max_delivery_attempts': 3,
            'retry_delay': 300,  # 5 minutes
            'alert_retention_days': 30,
            'email_enabled': os.environ.get('ALERT_EMAIL_ENABLED', 'true').lower() == 'true',
            'websocket_enabled': os.environ.get('WEBSOCKET_ENABLED', 'true').lower() == 'true',
            'severity_threshold': AlertSeverity.WARNING
        }
        
        logger.info("Alert manager initialized")
    
    def _get_smtp_config(self) -> Dict[str, Any]:
        """Get SMTP configuration"""
        return {
            'host': os.environ.get('SMTP_HOST', 'localhost'),
            'port': int(os.environ.get('SMTP_PORT', '587')),
            'user': os.environ.get('SMTP_USER', ''),
            'password': os.environ.get('SMTP_PASSWORD', ''),
            'use_tls': os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true',
            'use_ssl': os.environ.get('SMTP_USE_SSL', 'false').lower() == 'true',
            'from_email': os.environ.get('ALERT_EMAIL', 'alerts@maryv5.local'),
            'from_name': 'MARY V5 SHIELD CORE'
        }
    
    async def start(self):
        """Start alert manager"""
        try:
            logger.info("Starting alert manager")
            
            self.is_running = True
            
            # Start background tasks
            asyncio.create_task(self._process_alert_queue())
            asyncio.create_task(self._cleanup_old_alerts())
            
            logger.info("Alert manager started successfully")
            
        except Exception as e:
            logger.error(f"Error starting alert manager: {e}")
            raise
    
    async def stop(self):
        """Stop alert manager"""
        try:
            logger.info("Stopping alert manager")
            
            self.is_running = False
            
            logger.info("Alert manager stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping alert manager: {e}")
    
    async def create_alert(self, title: str, message: str, severity: AlertSeverity,
                         source: str = "system", details: Dict[str, Any] = None,
                         recipients: List[str] = None) -> str:
        """Create and queue alert"""
        try:
            alert_id = str(uuid.uuid4())
            
            alert = Alert(
                alert_id=alert_id,
                timestamp=datetime.utcnow(),
                severity=severity,
                title=title,
                message=message,
                source=source,
                details=details or {},
                recipients=recipients or [self.smtp_config['from_email']]
            )
            
            # Store alert
            self.alerts[alert_id] = alert
            
            # Queue for processing
            await self.alert_queue.put(alert)
            
            logger.info(f"Alert created: {alert_id} - {title}")
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    async def _process_alert_queue(self):
        """Process alert queue"""
        try:
            while self.is_running:
                try:
                    # Get alert from queue
                    alert = await asyncio.wait_for(self.alert_queue.get(), timeout=1.0)
                    
                    # Process alert
                    await self._process_alert(alert)
                    
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing alert queue: {e}")
                    await asyncio.sleep(5)
                    
        except Exception as e:
            logger.error(f"Alert queue processing error: {e}")
    
    async def _process_alert(self, alert: Alert):
        """Process individual alert"""
        try:
            # Check severity threshold
            if self._should_send_alert(alert):
                # Send email notification
                if self.config['email_enabled']:
                    await self._send_email_alert(alert)
                
                # Send WebSocket notification
                if self.config['websocket_enabled']:
                    await self._send_websocket_alert(alert)
                
                # Update alert status
                alert.status = AlertStatus.SENT
                alert.last_attempt = datetime.utcnow()
                
                logger.info(f"Alert processed: {alert.alert_id}")
            else:
                # Mark as acknowledged (below threshold)
                alert.status = AlertStatus.ACKNOWLEDGED
                logger.info(f"Alert below threshold, acknowledged: {alert.alert_id}")
                
        except Exception as e:
            logger.error(f"Error processing alert {alert.alert_id}: {e}")
            alert.status = AlertStatus.FAILED
            alert.last_attempt = datetime.utcnow()
    
    def _should_send_alert(self, alert: Alert) -> bool:
        """Check if alert should be sent based on severity"""
        severity_levels = {
            AlertSeverity.INFO: 0,
            AlertSeverity.WARNING: 1,
            AlertSeverity.ERROR: 2,
            AlertSeverity.CRITICAL: 3
        }
        
        alert_level = severity_levels.get(alert.severity, 0)
        threshold_level = severity_levels.get(self.config['severity_threshold'], 1)
        
        return alert_level >= threshold_level
    
    async def _send_email_alert(self, alert: Alert):
        """Send email alert"""
        try:
            # Check delivery attempts
            if alert.delivery_attempts >= self.config['max_delivery_attempts']:
                logger.warning(f"Max delivery attempts reached for alert {alert.alert_id}")
                return
            
            alert.delivery_attempts += 1
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[MARY V5 ALERT] {alert.title}"
            msg['From'] = formataddr((self.smtp_config['from_name'], self.smtp_config['from_email']))
            msg['To'] = ', '.join(alert.recipients)
            
            # HTML content
            html_content = self._generate_email_html(alert)
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email
            await self._send_email(msg)
            
            logger.info(f"Email alert sent: {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error sending email alert {alert.alert_id}: {e}")
            # Schedule retry
            if alert.delivery_attempts < self.config['max_delivery_attempts']:
                asyncio.create_task(self._retry_alert(alert))
    
    def _generate_email_html(self, alert: Alert) -> str:
        """Generate HTML email content"""
        severity_colors = {
            AlertSeverity.INFO: '#17a2b8',
            AlertSeverity.WARNING: '#ffc107',
            AlertSeverity.ERROR: '#dc3545',
            AlertSeverity.CRITICAL: '#721c24'
        }
        
        color = severity_colors.get(alert.severity, '#6c757d')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>MARY V5 SHIELD CORE - Alert</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; }}
                .container {{ max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background-color: {color}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ padding: 20px; }}
                .alert-info {{ margin: 10px 0; padding: 15px; background-color: #e9ecef; border-left: 4px solid {color}; }}
                .footer {{ margin-top: 20px; padding: 20px; background-color: #f8f9fa; border-radius: 0 0 8px 8px; font-size: 12px; color: #6c757d; }}
                .timestamp {{ color: #6c757d; font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>MARY V5 SHIELD CORE</h1>
                    <h2>Security Alert</h2>
                </div>
                <div class="content">
                    <h3>{alert.title}</h3>
                    <p class="timestamp">Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p><strong>Severity:</strong> {alert.severity.value.upper()}</p>
                    <p><strong>Source:</strong> {alert.source}</p>
                    <p><strong>Message:</strong></p>
                    <div class="alert-info">
                        {alert.message}
                    </div>
                    
                    {self._format_details_html(alert.details) if alert.details else ''}
                </div>
                <div class="footer">
                    <p>This alert was generated by MARY V5 SHIELD CORE v5.0 Enterprise</p>
                    <p>Alert ID: {alert.alert_id}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _format_details_html(self, details: Dict[str, Any]) -> str:
        """Format alert details as HTML"""
        if not details:
            return ""
        
        html = "<h4>Details:</h4><ul>"
        for key, value in details.items():
            html += f"<li><strong>{key}:</strong> {value}</li>"
        html += "</ul>"
        
        return html
    
    async def _send_email(self, msg: MIMEMultipart):
        """Send email via SMTP"""
        try:
            # Connect to SMTP server
            if self.smtp_config['use_ssl']:
                server = smtplib.SMTP_SSL(self.smtp_config['host'], self.smtp_config['port'])
            else:
                server = smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port'])
                
                if self.smtp_config['use_tls']:
                    server.starttls()
            
            # Login
            if self.smtp_config['user'] and self.smtp_config['password']:
                server.login(self.smtp_config['user'], self.smtp_config['password'])
            
            # Send email
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            raise
    
    async def _send_websocket_alert(self, alert: Alert):
        """Send WebSocket alert"""
        try:
            alert_data = alert.to_dict()
            
            # Send to all connected clients
            for client_callback in self.websocket_clients:
                try:
                    await client_callback({
                        'type': 'alert',
                        'data': alert_data
                    })
                except Exception as e:
                    logger.error(f"Error sending WebSocket alert to client: {e}")
                    
        except Exception as e:
            logger.error(f"Error sending WebSocket alert: {e}")
    
    async def _retry_alert(self, alert: Alert):
        """Retry failed alert delivery"""
        try:
            await asyncio.sleep(self.config['retry_delay'])
            await self._process_alert(alert)
            
        except Exception as e:
            logger.error(f"Error retrying alert {alert.alert_id}: {e}")
    
    async def _cleanup_old_alerts(self):
        """Cleanup old alerts"""
        try:
            while self.is_running:
                try:
                    # Cleanup every hour
                    await asyncio.sleep(3600)
                    
                    cutoff_time = datetime.utcnow() - timedelta(days=self.config['alert_retention_days'])
                    
                    # Remove old alerts
                    old_alerts = [
                        alert_id for alert_id, alert in self.alerts.items()
                        if alert.timestamp < cutoff_time
                    ]
                    
                    for alert_id in old_alerts:
                        del self.alerts[alert_id]
                        
                    if old_alerts:
                        logger.info(f"Cleaned up {len(old_alerts)} old alerts")
                        
                except Exception as e:
                    logger.error(f"Error in cleanup task: {e}")
                    
        except Exception as e:
            logger.error(f"Alert cleanup error: {e}")
    
    def add_websocket_client(self, callback: Callable):
        """Add WebSocket client"""
        self.websocket_clients.append(callback)
        logger.info(f"WebSocket client added (total: {len(self.websocket_clients)})")
    
    def remove_websocket_client(self, callback: Callable):
        """Remove WebSocket client"""
        if callback in self.websocket_clients:
            self.websocket_clients.remove(callback)
            logger.info(f"WebSocket client removed (total: {len(self.websocket_clients)})")
    
    def get_alerts(self, severity: Optional[AlertSeverity] = None, 
                   limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts with optional filtering"""
        try:
            alerts = list(self.alerts.values())
            
            # Filter by severity
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            # Sort by timestamp (most recent first)
            alerts.sort(key=lambda x: x.timestamp, reverse=True)
            
            # Limit results
            alerts = alerts[:limit]
            
            return [alert.to_dict() for alert in alerts]
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            total_alerts = len(self.alerts)
            
            # Count by severity
            severity_counts = {}
            for alert in self.alerts.values():
                severity_counts[alert.severity.value] = severity_counts.get(alert.severity.value, 0) + 1
            
            # Count by status
            status_counts = {}
            for alert in self.alerts.values():
                status_counts[alert.status.value] = status_counts.get(alert.status.value, 0) + 1
            
            return {
                'total_alerts': total_alerts,
                'severity_distribution': severity_counts,
                'status_distribution': status_counts,
                'websocket_clients': len(self.websocket_clients),
                'email_enabled': self.config['email_enabled'],
                'websocket_enabled': self.config['websocket_enabled'],
                'smtp_configured': bool(self.smtp_config['host'] and self.smtp_config['user'])
            }
            
        except Exception as e:
            logger.error(f"Error getting alert statistics: {e}")
            return {'error': str(e)}


# Global alert manager instance
alert_manager = AlertManager()


# API functions
async def start_alert_manager() -> str:
    """Start alert manager"""
    try:
        await alert_manager.start()
        logger.info("Alert manager started")
        return "Alert manager started successfully"
    except Exception as e:
        logger.error(f"Error starting alert manager: {e}")
        return f"Error starting alert manager: {e}"


async def stop_alert_manager() -> str:
    """Stop alert manager"""
    try:
        await alert_manager.stop()
        logger.info("Alert manager stopped")
        return "Alert manager stopped successfully"
    except Exception as e:
        logger.error(f"Error stopping alert manager: {e}")
        return f"Error stopping alert manager: {e}"


async def create_alert(title: str, message: str, severity: str,
                   source: str = "system", details: Dict[str, Any] = None,
                   recipients: List[str] = None) -> str:
    """Create alert"""
    try:
        severity_enum = AlertSeverity(severity.lower())
        return await alert_manager.create_alert(title, message, severity_enum, source, details, recipients)
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        return None


def get_alerts(severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Get alerts"""
    try:
        severity_enum = AlertSeverity(severity.lower()) if severity else None
        return alert_manager.get_alerts(severity_enum, limit)
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return []


def get_alert_statistics() -> Dict[str, Any]:
    """Get alert statistics"""
    try:
        return alert_manager.get_statistics()
    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}")
        return {'error': str(e)}


def add_websocket_client(callback: Callable):
    """Add WebSocket client"""
    try:
        alert_manager.add_websocket_client(callback)
        logger.info("WebSocket client added")
    except Exception as e:
        logger.error(f"Error adding WebSocket client: {e}")


def remove_websocket_client(callback: Callable):
    """Remove WebSocket client"""
    try:
        alert_manager.remove_websocket_client(callback)
        logger.info("WebSocket client removed")
    except Exception as e:
        logger.error(f"Error removing WebSocket client: {e}"


# Initialize alert manager
async def initialize_alert_manager() -> str:
    """Initialize alert manager"""
    try:
        await start_alert_manager()
        logger.info("Alert manager initialized")
        return "Alert manager initialized successfully"
    except Exception as e:
        logger.error(f"Error initializing alert manager: {e}")
        return f"Error initializing alert manager: {e}"


# Cleanup function
async def cleanup_alert_manager() -> str:
    """Cleanup alert manager"""
    try:
        await stop_alert_manager()
        logger.info("Alert manager cleaned up")
        return "Alert manager cleaned up successfully"
    except Exception as e:
        logger.error(f"Error cleaning up alert manager: {e}")
        return f"Error cleaning up alert manager: {e}"
