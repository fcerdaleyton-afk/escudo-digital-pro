"""
MARY V5 SHIELD CORE - Comprehensive Security Tests
Complete testing suite for all security components
"""

import pytest
import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from fastapi.testclient import TestClient
from httpx import AsyncClient
import websockets

# Import modules to test
from app.security.security_engine import (
    SecurityEngine, SecurityEvent, ThreatLevel, EventType,
    EventCorrelator, ThreatOrchestrator
)
from app.monitoring.live_alerts import (
    LiveAlertSystem, LiveAlert, AlertPriority, AlertStatus
)
from app.detection.windows_defender import (
    WindowsDefender, WindowsThreatType, ThreatSeverity
)
from app.security.threat_intelligence import (
    ThreatIntelligenceManager, IndicatorOfCompromise, IOCType, ReputationLevel
)
from app.middleware.api_hardening import (
    APIHardeningMiddleware, RequestValidator, DDoSProtection
)
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.core.audit_trail import (
    AuditTrailManager, AuditEvent, AuditEventType, AuditSeverity
)
from app.core.async_performance import (
    AsyncPerformanceOptimizer, AsyncTask, TaskPriority
)


class TestSecurityEngine:
    """Test security engine components"""
    
    @pytest.fixture
    def security_engine(self):
        """Create security engine instance"""
        return SecurityEngine()
    
    @pytest.fixture
    def sample_event(self):
        """Create sample security event"""
        return SecurityEvent(
            event_type=EventType.AUTHENTICATION_FAILURE,
            threat_level=ThreatLevel.MEDIUM,
            source_ip="192.168.1.100",
            user_id="test_user",
            description="Test authentication failure",
            details={"attempt_count": 3}
        )
    
    @pytest.mark.asyncio
    async def test_security_engine_initialization(self, security_engine):
        """Test security engine initialization"""
        assert security_engine.enabled == True
        assert len(security_engine.processing_workers) == 0
        assert security_engine.event_queue.qsize() == 0
    
    @pytest.mark.asyncio
    async def test_security_engine_start_stop(self, security_engine):
        """Test security engine start and stop"""
        await security_engine.start()
        assert len(security_engine.processing_workers) > 0
        
        await security_engine.stop()
        assert len(security_engine.processing_workers) == 0
    
    @pytest.mark.asyncio
    async def test_event_processing(self, security_engine, sample_event):
        """Test event processing"""
        await security_engine.start()
        
        # Process event
        result = await security_engine.process_event(sample_event.to_dict())
        
        # Wait for processing
        await asyncio.sleep(0.1)
        
        # Check statistics
        stats = security_engine.get_engine_status()
        assert stats["statistics"]["events_processed"] >= 1
        
        await security_engine.stop()
    
    def test_event_correlator(self):
        """Test event correlation"""
        correlator = EventCorrelator()
        
        # Create correlated events
        events = [
            SecurityEvent(
                event_type=EventType.AUTHENTICATION_FAILURE,
                source_ip="192.168.1.100",
                details={"attempt_count": 1}
            ),
            SecurityEvent(
                event_type=EventType.AUTHENTICATION_FAILURE,
                source_ip="192.168.1.100",
                details={"attempt_count": 2}
            ),
            SecurityEvent(
                event_type=EventType.AUTHENTICATION_FAILURE,
                source_ip="192.168.1.100",
                details={"attempt_count": 3}
            )
        ]
        
        # Test correlation
        correlations = []
        for event in events:
            event_correlations = asyncio.run(correlator.correlate_events(event))
            correlations.extend(event_correlations)
        
        assert len(correlations) > 0
        assert any("repeated_auth_failures" in str(c.pattern_name) for c in correlations)
    
    def test_threat_orchestrator(self):
        """Test threat orchestrator"""
        orchestrator = ThreatOrchestrator()
        
        # Create threat event
        threat_event = SecurityEvent(
            event_type=EventType.THREAT_DETECTED,
            threat_level=ThreatLevel.HIGH,
            source_ip="192.168.1.100",
            description="High threat detected"
        )
        
        # Process threat
        incident = asyncio.run(orchestrator.process_event(threat_event))
        
        assert incident is not None
        assert incident.threat_level == ThreatLevel.HIGH
        assert incident.source_events == [threat_event.id]


class TestLiveAlertSystem:
    """Test live alert system"""
    
    @pytest.fixture
    def alert_system(self):
        """Create alert system instance"""
        return LiveAlertSystem()
    
    @pytest.mark.asyncio
    async def test_alert_creation(self, alert_system):
        """Test alert creation"""
        alert_id = await alert_system.create_alert(
            priority=AlertPriority.HIGH,
            category=AlertCategory.SECURITY,
            title="Test Alert",
            description="This is a test alert",
            details={"test": True}
        )
        
        assert alert_id is not None
        assert len(alert_id) > 0
    
    @pytest.mark.asyncio
    async def test_alert_acknowledgment(self, alert_system):
        """Test alert acknowledgment"""
        # Create alert
        alert_id = await alert_system.create_alert(
            priority=AlertPriority.MEDIUM,
            category=AlertCategory.SYSTEM,
            title="Test Alert",
            description="Test alert for acknowledgment"
        )
        
        # Acknowledge alert
        result = await alert_system.acknowledge_alert(alert_id, "test_user")
        
        assert result == True
    
    @pytest.mark.asyncio
    async def test_alert_resolution(self, alert_system):
        """Test alert resolution"""
        # Create alert
        alert_id = await alert_system.create_alert(
            priority=AlertPriority.LOW,
            category=AlertCategory.PERFORMANCE,
            title="Test Alert",
            description="Test alert for resolution"
        )
        
        # Resolve alert
        result = await alert_system.resolve_alert(alert_id, "test_user", "Issue resolved")
        
        assert result == True
    
    def test_alert_statistics(self, alert_system):
        """Test alert statistics"""
        stats = alert_system.get_system_stats()
        
        assert "enabled" in stats
        assert "active_alerts" in stats
        assert "total_alerts" in stats
        assert "websocket_connections" in stats


class TestWindowsDefender:
    """Test Windows defender analyzer"""
    
    @pytest.fixture
    def windows_defender(self):
        """Create Windows defender instance"""
        return WindowsDefender()
    
    @pytest.mark.asyncio
    async def test_scheduled_task_analysis(self, windows_defender):
        """Test scheduled task analysis"""
        threats = await windows_defender.task_analyzer.analyze_scheduled_tasks()
        
        assert isinstance(threats, list)
        # Should not crash even if no threats detected
    
    @pytest.mark.asyncio
    async def test_registry_analysis(self, windows_defender):
        """Test registry analysis"""
        threats = await windows_defender.registry_analyzer.analyze_registry_autoruns()
        
        assert isinstance(threats, list)
        # Should not crash even if no threats detected
    
    @pytest.mark.asyncio
    async def test_powershell_analysis(self, windows_defender):
        """Test PowerShell analysis"""
        threats = await windows_defender.powershell_analyzer.analyze_powershell_processes()
        
        assert isinstance(threats, list)
        # Should not crash even if no threats detected
    
    @pytest.mark.asyncio
    async def test_startup_analysis(self, windows_defender):
        """Test startup folder analysis"""
        threats = await windows_defender.startup_analyzer.analyze_startup_folders()
        
        assert isinstance(threats, list)
        # Should not crash even if no threats detected
    
    def test_windows_threat_summary(self, windows_defender):
        """Test Windows threat summary"""
        summary = windows_defender.get_windows_threat_summary()
        
        assert "enabled" in summary
        assert "total_threats" in summary
        assert "threat_types" in summary
        assert "is_windows" in summary


class TestThreatIntelligence:
    """Test threat intelligence module"""
    
    @pytest.fixture
    def threat_intel(self):
        """Create threat intelligence manager"""
        return ThreatIntelligenceManager()
    
    @pytest.mark.asyncio
    async def test_ioc_reputation_check(self, threat_intel):
        """Test IOC reputation check"""
        # Test IP reputation
        result = await threat_intel.check_reputation("ip_address", "192.168.1.100")
        
        assert "reputation" in result
        assert "confidence" in result
        assert "source" in result
    
    @pytest.mark.asyncio
    async def test_ioc_addition(self, threat_intel):
        """Test IOC addition"""
        ioc = IndicatorOfCompromise(
            ioc_type=IOCType.IP_ADDRESS,
            value="192.168.1.200",
            reputation=ReputationLevel.MALICIOUS,
            source="test",
            confidence=0.9
        )
        
        result = await threat_intel.add_ioc(ioc)
        assert result == True
    
    @pytest.mark.asyncio
    async def test_threat_intel_stats(self, threat_intel):
        """Test threat intelligence statistics"""
        stats = threat_intel.get_threat_intel_stats()
        
        assert "enabled" in stats
        assert "cache_stats" in stats
        assert "database_stats" in stats
        assert "ingestion_stats" in stats


class TestAPIHardening:
    """Test API hardening middleware"""
    
    @pytest.fixture
    def api_hardening(self):
        """Create API hardening middleware"""
        from fastapi import FastAPI
        app = FastAPI()
        return APIHardeningMiddleware(app)
    
    def test_request_validation(self, api_hardening):
        """Test request validation"""
        validator = api_hardening.request_validator
        
        # Create mock request
        request = Mock()
        request.method = "GET"
        request.url.path = "/api/test"
        request.url.query = ""
        request.headers = {"user-agent": "Test Browser"}
        request.client.host = "192.168.1.100"
        
        # Validate request
        violations = validator.validate_request(request)
        
        assert isinstance(violations, list)
    
    def test_ddos_protection(self, api_hardening):
        """Test DDoS protection"""
        ddos = api_hardening.ddos_protection
        
        # Create mock request
        request = Mock()
        request.method = "GET"
        request.headers = {"user-agent": "Test Browser"}
        request.client.host = "192.168.1.100"
        
        # Check request
        violation = ddos.check_request(request)
        
        # Should not block normal request
        assert violation is None or not violation.blocked
    
    def test_abuse_detection(self, api_hardening):
        """Test abuse detection"""
        abuse_detector = api_hardening.abuse_detector
        
        # Create mock request
        request = Mock()
        request.method = "POST"
        request.url.path = "/api/v1/auth/login"
        request.headers = {"user-agent": "Test Browser"}
        request.client.host = "192.168.1.100"
        
        # Detect abuse
        violations = abuse_detector.detect_abuse(request)
        
        assert isinstance(violations, list)


class TestSecurityHeaders:
    """Test security headers middleware"""
    
    @pytest.fixture
    def security_headers(self):
        """Create security headers middleware"""
        from fastapi import FastAPI
        app = FastAPI()
        return SecurityHeadersMiddleware(app)
    
    def test_headers_application(self, security_headers):
        """Test security headers application"""
        # Create mock request and response
        request = Mock()
        request.method = "GET"
        request.url.scheme = "https"
        request.headers = {"user-agent": "Test Browser"}
        
        response = Mock()
        response.headers = {}
        
        # Apply headers
        asyncio.run(security_headers._add_security_headers(request, response))
        
        # Check essential headers
        assert "X-Frame-Options" in response.headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Security-Context" in response.headers
    
    def test_csp_generation(self, security_headers):
        """Test CSP header generation"""
        request = Mock()
        request.method = "GET"
        
        csp_value = security_headers._generate_csp_header(request)
        
        assert "default-src" in csp_value
        assert "script-src" in csp_value
        assert "style-src" in csp_value
    
    def test_csp_violation_handling(self, security_headers):
        """Test CSP violation handling"""
        violation_data = {
            "blocked-uri": "javascript:alert('xss')",
            "violated-directive": "script-src",
            "document-uri": "https://example.com"
        }
        
        request = Mock()
        
        # Handle violation
        asyncio.run(security_headers.handle_csp_violation(request, violation_data))
        
        # Should not crash
        assert True


class TestAuditTrail:
    """Test audit trail system"""
    
    @pytest.fixture
    def audit_trail(self):
        """Create audit trail manager"""
        return AuditTrailManager()
    
    @pytest.mark.asyncio
    async def test_audit_event_logging(self, audit_trail):
        """Test audit event logging"""
        event_id = await audit_trail.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            severity=AuditSeverity.INFO,
            user_id="test_user",
            ip_address="192.168.1.100",
            action="login",
            result="success"
        )
        
        assert event_id != ""
    
    @pytest.mark.asyncio
    async def test_audit_event_retrieval(self, audit_trail):
        """Test audit event retrieval"""
        # Log some events
        await audit_trail.log_event(
            event_type=AuditEventType.API_ACCESS,
            user_id="test_user"
        )
        
        await audit_trail.log_event(
            event_type=AuditEventType.DATA_ACCESS,
            user_id="test_user"
        )
        
        # Retrieve events
        events = await audit_trail.get_audit_events(limit=10)
        
        assert isinstance(events, list)
        assert len(events) >= 2
    
    @pytest.mark.asyncio
    async def test_audit_summary(self, audit_trail):
        """Test audit summary"""
        summary = await audit_trail.get_audit_summary(days=7)
        
        assert "period_days" in summary
        assert "total_events" in summary
        assert "events_by_type" in summary
        assert "unique_users" in summary


class TestAsyncPerformance:
    """Test async performance optimizer"""
    
    @pytest.fixture
    def perf_optimizer(self):
        """Create async performance optimizer"""
        return AsyncPerformanceOptimizer()
    
    @pytest.mark.asyncio
    async def test_task_submission(self, perf_optimizer):
        """Test task submission"""
        # Create simple task
        async def test_task():
            await asyncio.sleep(0.1)
            return "task_result"
        
        # Submit task
        task_id = await perf_optimizer.submit_task(test_task(), TaskPriority.HIGH)
        
        assert task_id != "immediate"
    
    @pytest.mark.asyncio
    async def test_cache_operations(self, perf_optimizer):
        """Test cache operations"""
        # Set cache value
        await perf_optimizer.cache.set("test_key", "test_value")
        
        # Get cache value
        cached_value = await perf_optimizer.cache.get("test_key")
        
        assert cached_value == "test_value"
        
        # Delete cache value
        deleted = await perf_optimizer.cache.delete("test_key")
        
        assert deleted == True
        
        # Try to get deleted value
        cached_value = await perf_optimizer.cache.get("test_key")
        
        assert cached_value is None
    
    @pytest.mark.asyncio
    async def test_cache_decorator(self, perf_optimizer):
        """Test cache decorator"""
        @perf_optimizer.cache_result(ttl=60)
        async def expensive_function(x, y):
            await asyncio.sleep(0.1)
            return x + y
        
        # First call (should compute)
        start_time = time.time()
        result1 = await expensive_function(1, 2)
        first_call_time = time.time() - start_time
        
        # Second call (should use cache)
        start_time = time.time()
        result2 = await expensive_function(1, 2)
        second_call_time = time.time() - start_time
        
        assert result1 == result2
        assert second_call_time < first_call_time
    
    def test_performance_stats(self, perf_optimizer):
        """Test performance statistics"""
        stats = perf_optimizer.get_performance_summary()
        
        assert "enabled" in stats
        assert "worker_pool" in stats
        assert "cache" in stats
        assert "memory_manager" in stats


class TestIntegration:
    """Integration tests for security components"""
    
    @pytest.mark.asyncio
    async def test_full_security_pipeline(self):
        """Test complete security pipeline"""
        # Create security engine
        security_engine = SecurityEngine()
        await security_engine.start()
        
        try:
            # Create security event
            event_data = {
                "event_type": "authentication_failure",
                "threat_level": "medium",
                "source_ip": "192.168.1.100",
                "user_id": "test_user",
                "description": "Test authentication failure",
                "details": {"attempt_count": 3}
            }
            
            # Process event
            result = await security_engine.process_event(event_data)
            
            # Wait for processing
            await asyncio.sleep(0.1)
            
            # Check results
            stats = security_engine.get_engine_status()
            assert stats["statistics"]["events_processed"] >= 1
            
        finally:
            await security_engine.stop()
    
    @pytest.mark.asyncio
    async def test_alert_system_integration(self):
        """Test alert system integration"""
        alert_system = LiveAlertSystem()
        websocket_server = await alert_system.start()
        
        try:
            # Create high-priority alert
            alert_id = await alert_system.create_alert(
                priority=AlertPriority.CRITICAL,
                category=AlertCategory.SECURITY,
                title="Critical Security Alert",
                description="Test critical alert",
                details={"threat_level": "critical"}
            )
            
            # Get active alerts
            active_alerts = alert_system.get_active_alerts(10)
            
            assert len(active_alerts) >= 1
            assert any(alert["id"] == alert_id for alert in active_alerts)
            
        finally:
            await alert_system.stop()
    
    @pytest.mark.asyncio
    async def test_threat_intel_integration(self):
        """Test threat intelligence integration"""
        threat_intel = ThreatIntelligenceManager()
        await threat_intel.start()
        
        try:
            # Add malicious IOC
            ioc = IndicatorOfCompromise(
                ioc_type=IOCType.IP_ADDRESS,
                value="192.168.1.100",
                reputation=ReputationLevel.MALICIOUS,
                source="test",
                confidence=0.9
            )
            
            await threat_intel.add_ioc(ioc)
            
            # Check reputation
            result = await threat_intel.check_reputation("ip_address", "192.168.1.100")
            
            assert result["reputation"] == "malicious"
            assert result["confidence"] == 0.9
            
        finally:
            await threat_intel.stop()


class TestPerformance:
    """Performance and load tests"""
    
    @pytest.mark.asyncio
    async def test_security_engine_load(self):
        """Test security engine under load"""
        security_engine = SecurityEngine()
        await security_engine.start()
        
        try:
            # Generate load
            tasks = []
            for i in range(100):
                event_data = {
                    "event_type": "api_access",
                    "threat_level": "low",
                    "source_ip": f"192.168.1.{i % 255}",
                    "description": f"Load test event {i}"
                }
                task = asyncio.create_task(security_engine.process_event(event_data))
                tasks.append(task)
            
            # Wait for all tasks
            start_time = time.time()
            await asyncio.gather(*tasks)
            end_time = time.time()
            
            # Check performance
            duration = end_time - start_time
            assert duration < 5.0  # Should complete within 5 seconds
            
            stats = security_engine.get_engine_status()
            assert stats["statistics"]["events_processed"] >= 100
            
        finally:
            await security_engine.stop()
    
    @pytest.mark.asyncio
    async def test_alert_system_load(self):
        """Test alert system under load"""
        alert_system = LiveAlertSystem()
        await alert_system.start()
        
        try:
            # Generate load
            tasks = []
            for i in range(50):
                task = asyncio.create_task(alert_system.create_alert(
                    priority=AlertPriority.MEDIUM,
                    category=AlertCategory.SECURITY,
                    title=f"Load Test Alert {i}",
                    description=f"Load test alert {i}"
                ))
                tasks.append(task)
            
            # Wait for all tasks
            start_time = time.time()
            await asyncio.gather(*tasks)
            end_time = time.time()
            
            # Check performance
            duration = end_time - start_time
            assert duration < 3.0  # Should complete within 3 seconds
            
            stats = alert_system.get_system_stats()
            assert stats["total_alerts"] >= 50
            
        finally:
            await alert_system.stop()
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test concurrent operations"""
        # Start multiple components
        security_engine = SecurityEngine()
        alert_system = LiveAlertSystem()
        threat_intel = ThreatIntelligenceManager()
        
        await security_engine.start()
        websocket_server = await alert_system.start()
        await threat_intel.start()
        
        try:
            # Run concurrent operations
            tasks = []
            
            # Security events
            for i in range(20):
                event_data = {
                    "event_type": "authentication_failure",
                    "threat_level": "medium",
                    "source_ip": f"192.168.1.{i % 255}",
                    "description": f"Concurrent test {i}"
                }
                tasks.append(security_engine.process_event(event_data))
            
            # Alerts
            for i in range(10):
                tasks.append(alert_system.create_alert(
                    priority=AlertPriority.HIGH,
                    category=AlertCategory.SECURITY,
                    title=f"Concurrent Alert {i}",
                    description=f"Concurrent alert {i}"
                ))
            
            # IOC checks
            for i in range(15):
                tasks.append(threat_intel.check_reputation(
                    "ip_address", f"192.168.1.{i % 255}"
                ))
            
            # Wait for all operations
            start_time = time.time()
            await asyncio.gather(*tasks)
            end_time = time.time()
            
            # Check performance
            duration = end_time - start_time
            assert duration < 5.0  # Should complete within 5 seconds
            
        finally:
            await security_engine.stop()
            await alert_system.stop()
            await threat_intel.stop()


# Test configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "asyncio: mark test to run with asyncio"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security test"
    )


if __name__ == "__main__":
    # Run tests
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-m", "security",
        "--disable-warnings"
    ])
