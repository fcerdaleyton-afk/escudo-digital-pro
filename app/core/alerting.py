"""
Production-grade Alerting System for Mary V5
Real-time threat visibility and operational monitoring
"""

import os
import asyncio
import json
import time
import smtplib
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.config import settings


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertChannel(Enum):
    """Alert delivery channels"""
    EMAIL = "email"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    LOG = "log"


@dataclass
class AlertEvent:
    """Alert event data structure"""
    timestamp: datetime
    severity: AlertSeverity
    category: str
    title: str
    message: str
    source_ip: str
    attack_type: str
    threat_level: str
    fingerprint: str
    details: Dict[str, Any]
    correlation_id: str
    channels: List[AlertChannel]
    metadata: Dict[str, Any] = None


class AlertRateLimiter:
    """Rate limiting for alerts to prevent spam"""
    
    def __init__(self):
        self.alert_history = {}
        self.rate_limits = {
            AlertSeverity.LOW: timedelta(hours=1),
            AlertSeverity.MEDIUM: timedelta(minutes=30),
            AlertSeverity.HIGH: timedelta(minutes=10),
            AlertSeverity.CRITICAL: timedelta(minutes=1),
        }
    
    def should_send_alert(self, alert: AlertEvent) -> bool:
        """Check if alert should be sent based on rate limits"""
        key = f"{alert.severity.value}_{alert.category}_{alert.source_ip}"
        current_time = datetime.utcnow()
        
        if key not in self.alert_history:
            self.alert_history[key] = []
        
        # Clean old alerts
        rate_limit = self.rate_limits[alert.severity]
        cutoff_time = current_time - rate_limit
        
        self.alert_history[key] = [
            alert_time for alert_time in self.alert_history[key]
            if alert_time > cutoff_time
        ]
        
        # Check if we can send another alert
        if len(self.alert_history[key]) >= 3:  # Max 3 alerts per time window
            return False
        
        self.alert_history[key].append(current_time)
        return True


class EmailAlertManager:
    """Email alert management"""
    
    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("ALERT_FROM_EMAIL", "alerts@mary-v5.com")
        self.to_emails = os.getenv("ALERT_TO_EMAILS", "").split(",") if os.getenv("ALERT_TO_EMAILS") else []
        self.enabled = bool(self.smtp_username and self.smtp_password and self.to_emails)
    
    async def send_alert(self, alert: AlertEvent) -> bool:
        """Send email alert"""
        if not self.enabled:
            return False
        
        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ", ".join(self.to_emails)
            msg['Subject'] = f"[MARY-V5 ALERT] {alert.severity.value.upper()}: {alert.title}"
            
            # Email body
            body = f"""
MARY V5 SECURITY ALERT

Severity: {alert.severity.value.upper()}
Category: {alert.category}
Timestamp: {alert.timestamp.isoformat()}
Source IP: {alert.source_ip}
Attack Type: {alert.attack_type}
Threat Level: {alert.threat_level}
Correlation ID: {alert.correlation_id}

Message:
{alert.message}

Details:
{json.dumps(alert.details, indent=2)}

Fingerprint: {alert.fingerprint}

---
This is an automated alert from Mary V5 Security System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            text = msg.as_string()
            server.sendmail(self.from_email, self.to_emails, text)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
            return False


class TelegramAlertManager:
    """Telegram webhook alert management"""
    
    def __init__(self):
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.webhook_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        self.enabled = bool(self.bot_token and self.chat_id)
    
    async def send_alert(self, alert: AlertEvent) -> bool:
        """Send Telegram alert"""
        if not self.enabled:
            return False
        
        try:
            # Format message for Telegram
            severity_emoji = {
                AlertSeverity.LOW: "🟡",
                AlertSeverity.MEDIUM: "🟠", 
                AlertSeverity.HIGH: "🔴",
                AlertSeverity.CRITICAL: "🚨"
            }
            
            message = f"""
{severity_emoji.get(alert.severity, "⚠️")} <b>MARY V5 SECURITY ALERT</b>

<b>Severity:</b> {alert.severity.value.upper()}
<b>Category:</b> {alert.category}
<b>Source IP:</b> <code>{alert.source_ip}</code>
<b>Attack Type:</b> {alert.attack_type}
<b>Time:</b> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

<b>Message:</b>
{alert.message}

<b>Fingerprint:</b> <code>{alert.fingerprint}</code>
<b>Correlation ID:</b> <code>{alert.correlation_id}</code>
            """
            
            # Send to Telegram
            async with aiohttp.ClientSession() as session:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': 'HTML',
                    'disable_web_page_preview': True
                }
                
                async with session.post(self.webhook_url, json=payload) as response:
                    return response.status == 200
            
        except Exception as e:
            print(f"Failed to send Telegram alert: {e}")
            return False


class WebhookAlertManager:
    """Generic webhook alert management"""
    
    def __init__(self):
        self.webhook_url = os.getenv("ALERT_WEBHOOK_URL", "")
        self.webhook_headers = json.loads(os.getenv("ALERT_WEBHOOK_HEADERS", "{}"))
        self.enabled = bool(self.webhook_url)
    
    async def send_alert(self, alert: AlertEvent) -> bool:
        """Send webhook alert"""
        if not self.enabled:
            return False
        
        try:
            payload = {
                'timestamp': alert.timestamp.isoformat(),
                'severity': alert.severity.value,
                'category': alert.category,
                'title': alert.title,
                'message': alert.message,
                'source_ip': alert.source_ip,
                'attack_type': alert.attack_type,
                'threat_level': alert.threat_level,
                'fingerprint': alert.fingerprint,
                'correlation_id': alert.correlation_id,
                'details': alert.details,
                'metadata': alert.metadata
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers=self.webhook_headers
                ) as response:
                    return response.status == 200
            
        except Exception as e:
            print(f"Failed to send webhook alert: {e}")
            return False


class AlertManager:
    """Main alert management system"""
    
    def __init__(self):
        self.rate_limiter = AlertRateLimiter()
        self.email_manager = EmailAlertManager()
        self.telegram_manager = TelegramAlertManager()
        self.webhook_manager = WebhookAlertManager()
        self.enabled = os.getenv("ALERTING_ENABLED", "true").lower() == "true"
        
        # Alert severity thresholds
        self.email_threshold = AlertSeverity[os.getenv("EMAIL_ALERT_THRESHOLD", "HIGH")]
        self.telegram_threshold = AlertSeverity[os.getenv("TELEGRAM_ALERT_THRESHOLD", "CRITICAL")]
        self.webhook_threshold = AlertSeverity[os.getenv("WEBHOOK_ALERT_THRESHOLD", "MEDIUM")]
    
    async def send_alert(self, alert: AlertEvent) -> bool:
        """Send alert through appropriate channels"""
        if not self.enabled:
            return False
        
        # Check rate limiting
        if not self.rate_limiter.should_send_alert(alert):
            return False
        
        # Determine which channels to use
        channels_to_use = []
        
        if AlertChannel.EMAIL in alert.channels and alert.severity.value >= self.email_threshold.value:
            channels_to_use.append(self.email_manager)
        
        if AlertChannel.TELEGRAM in alert.channels and alert.severity.value >= self.telegram_threshold.value:
            channels_to_use.append(self.telegram_manager)
        
        if AlertChannel.WEBHOOK in alert.channels and alert.severity.value >= self.webhook_threshold.value:
            channels_to_use.append(self.webhook_manager)
        
        # Send alerts concurrently
        if channels_to_use:
            tasks = [manager.send_alert(alert) for manager in channels_to_use]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return any(result for result in results if isinstance(result, bool))
        
        return False
    
    def create_threat_alert(self, threat_event, correlation_id: str) -> AlertEvent:
        """Create alert from threat event"""
        # Map threat levels to alert severities
        severity_mapping = {
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL
        }
        
        severity = severity_mapping.get(threat_event.threat_level.value, AlertSeverity.MEDIUM)
        
        # Determine channels based on severity
        channels = [AlertChannel.LOG]
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            channels.extend([AlertChannel.EMAIL, AlertChannel.TELEGRAM])
        if severity in [AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            channels.append(AlertChannel.WEBHOOK)
        
        return AlertEvent(
            timestamp=threat_event.timestamp,
            severity=severity,
            category="security_threat",
            title=f"Security Threat: {threat_event.attack_type.value}",
            message=f"Detected {threat_event.attack_type.value} attack from {threat_event.source_ip}",
            source_ip=threat_event.source_ip,
            attack_type=threat_event.attack_type.value,
            threat_level=threat_event.threat_level.value,
            fingerprint=threat_event.fingerprint,
            details=threat_event.details,
            correlation_id=correlation_id,
            channels=channels,
            metadata={
                "blocked": threat_event.blocked,
                "duration_minutes": threat_event.duration_minutes
            }
        )
    
    def create_operational_alert(self, title: str, message: str, severity: AlertSeverity = AlertSeverity.MEDIUM, details: Dict[str, Any] = None) -> AlertEvent:
        """Create operational alert"""
        channels = [AlertChannel.LOG]
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            channels.extend([AlertChannel.EMAIL])
        
        return AlertEvent(
            timestamp=datetime.utcnow(),
            severity=severity,
            category="operational",
            title=title,
            message=message,
            source_ip="system",
            attack_type="operational",
            threat_level="operational",
            fingerprint="",  # Generate unique ID
            details=details or {},
            correlation_id="",  # System-generated
            channels=channels
        )


# Global alert manager instance
alert_manager = AlertManager()


# Utility functions
async def send_threat_alert(threat_event, correlation_id: str):
    """Send threat alert"""
    alert = alert_manager.create_threat_alert(threat_event, correlation_id)
    await alert_manager.send_alert(alert)


async def send_operational_alert(title: str, message: str, severity: AlertSeverity = AlertSeverity.MEDIUM, details: Dict[str, Any] = None):
    """Send operational alert"""
    alert = alert_manager.create_operational_alert(title, message, severity, details)
    await alert_manager.send_alert(alert)


async def send_security_alert(event: Dict[str, Any], correlation_id: str = None) -> bool:
    """Send security alert from centralized logging"""
    severity_str = event.get('severity', '').upper()
    severity = AlertSeverity.__members__.get(severity_str, AlertSeverity.MEDIUM)
    metadata = event.get('details', {}) if isinstance(event.get('details'), dict) else {}

    alert = AlertEvent(
        timestamp=datetime.fromisoformat(event.get('timestamp')) if event.get('timestamp') else datetime.utcnow(),
        severity=severity,
        category=event.get('category', 'security_event'),
        title=f"Security Event: {event.get('category', 'security')}",
        message=json.dumps(metadata) if metadata else event.get('category', 'Security event triggered'),
        source_ip=metadata.get('source_ip', 'system') if isinstance(metadata, dict) else 'system',
        attack_type=metadata.get('attack_type', 'security_event') if isinstance(metadata, dict) else 'security_event',
        threat_level=severity.value,
        fingerprint=metadata.get('fingerprint', ''),
        details=metadata,
        correlation_id=correlation_id or event.get('correlation_id', ''),
        channels=[AlertChannel.LOG, AlertChannel.WEBHOOK] if severity in [AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL] else [AlertChannel.LOG],
        metadata=metadata
    )

    return await alert_manager.send_alert(alert)


def is_alerting_enabled() -> bool:
    """Check if alerting is enabled"""
    return alert_manager.enabled
