"""
MARY V5 SHIELD CORE - Final Hardening Phase Test Suite
Comprehensive testing for all FINAL HARDENING PHASE components
"""

import os
import sys
import time
import asyncio
import pytest
import aiohttp
import json
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor
import websockets
import subprocess
import hashlib
import base64

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from app.core.security_settings import SecuritySettings, SecurityConfigManager, get_security_settings
from app.core.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitState, get_circuit_breaker_metrics
from app.security.rate_engine import SecurityRateEngine, RateLimitConfig, RiskLevel, ViolationType
from app.monitoring.threat_stream import LiveThreatStream, ThreatEvent, ThreatSeverity, ThreatCategory
from app.security.process_guard import ProcessGuard, ProcessEvent, ProcessRiskLevel, ProcessViolationType
from app.telemetry.telemetry_engine import TelemetryEngine, get_prometheus_metrics, get_telemetry_statistics
from app.security.incident_response import IncidentResponseEngine, Incident, IncidentSeverity, IncidentStatus
from app.core.task_manager import SecureAsyncTaskManager, TaskPriority, TaskStatus
from app.core.security_cache import SecurityCacheManager, CacheType, CacheEvictionPolicy


class TestSecuritySettings:
    """Test global security configuration"""
    
    @pytest.fixture
    async def security_config_manager(self):
        """Create security config manager"""
        manager = SecurityConfigManager()
        await manager.load_configuration()
        return manager
    
    @pytest.mark.asyncio
    async def test_security_configuration_validation(self, security_config_manager):
        """Test security configuration validation"""
        config = await security_config_manager.get_configuration()
        
        assert config is not None
        assert config.security_level in ["low", "medium", "high", "critical"]
        assert config.security_engine_enabled is True
        assert config.rate_limiting_enabled is True
        assert config.monitoring_enabled is True
    
    @pytest.mark.asyncio
    async def test_environment_validation(self, security_config_manager):
        """Test environment-specific validation"""
        config = await security_config_manager.get_configuration()
        
        if config.environment == "production":
            assert config.debug_enabled is False
            assert config.security_level in ["high", "critical"]
            assert len(config.jwt_secret) >= 32
    
    @pytest.mark.asyncio
    async def test_configuration_summary(self, security_config_manager):
        """Test configuration summary generation"""
        summary = security_config_manager.get_configuration_summary()
        
        assert "enabled" in summary
        assert "components" in summary
        assert "environment" in summary
        assert "security_level" in summary


class TestCircuitBreaker:
    """Test circuit breaker system"""
    
    @pytest.fixture
    def circuit_breaker(self):
        """Create circuit breaker"""
        config = CircuitBreakerConfig(
            name="test_breaker",
            failure_threshold=3,
            timeout=5.0,
            recovery_timeout=2.0
        )
        return CircuitBreaker(config)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_basic_operation(self, circuit_breaker):
        """Test basic circuit breaker operation"""
        # Test successful call
        async def success_func():
            return "success"
        
        result = await circuit_breaker.call(success_func)
        assert result == "success"
        assert circuit_breaker.get_state() == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_failure_handling(self, circuit_breaker):
        """Test circuit breaker failure handling"""
        async def failing_func():
            raise ValueError("Test error")
        
        # Trigger failures
        for _ in range(3):
            try:
                await circuit_breaker.call(failing_func)
            except ValueError:
                pass
        
        # Circuit should be open
        assert circuit_breaker.get_state() == CircuitState.OPEN
        
        # Calls should fail fast
        with pytest.raises(Exception):
            await circuit_breaker.call(success_func)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self, circuit_breaker):
        """Test circuit breaker recovery"""
        async def failing_func():
            raise ValueError("Test error")
        
        async def success_func():
            return "success"
        
        # Trigger failures to open circuit
        for _ in range(3):
            try:
                await circuit_breaker.call(failing_func)
            except ValueError:
                pass
        
        assert circuit_breaker.get_state() == CircuitState.OPEN
        
        # Wait for recovery timeout
        await asyncio.sleep(2.1)
        
        # Next call should succeed
        result = await circuit_breaker.call(success_func)
        assert result == "success"
        assert circuit_breaker.get_state() == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_metrics(self, circuit_breaker):
        """Test circuit breaker metrics"""
        async def success_func():
            return "success"
        
        async def failing_func():
            raise ValueError("Test error")
        
        # Generate some activity
        for _ in range(5):
            try:
                await circuit_breaker.call(success_func)
            except:
                pass
        
        for _ in range(3):
            try:
                await circuit_breaker.call(failing_func)
            except:
                pass
        
        metrics = circuit_breaker.get_metrics()
        assert metrics["total_calls"] > 0
        assert metrics["successful_calls"] > 0
        assert metrics["failed_calls"] > 0


class TestRateEngine:
    """Test security rate engine"""
    
    @pytest.fixture
    def rate_engine(self):
        """Create rate engine"""
        return SecurityRateEngine()
    
    @pytest.mark.asyncio
    async def test_rate_limiting_basic(self, rate_engine):
        """Test basic rate limiting"""
        config = RateLimitConfig(
            name="test_limiter",
            requests_per_second=10,
            burst_size=20,
            window_size=60
        )
        
        limiter = rate_engine.create_rate_limiter("test", **config.__dict__)
        
        request_data = {
            "ip_address": "192.168.1.1",
            "user_agent": "test-agent"
        }
        
        # First requests should pass
        for i in range(5):
            result = await limiter.check_rate_limit("test_user", request_data)
            assert result.allowed is True
            assert result.remaining_requests > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting_exceeded(self, rate_engine):
        """Test rate limit exceeded"""
        config = RateLimitConfig(
            name="test_limiter",
            requests_per_second=2,
            burst_size=3,
            window_size=60
        )
        
        limiter = rate_engine.create_rate_limiter("test", **config.__dict__)
        
        request_data = {
            "ip_address": "192.168.1.1",
            "user_agent": "test-agent"
        }
        
        # Exceed rate limit
        for i in range(10):
            result = await limiter.check_rate_limit("test_user", request_data)
            if not result.allowed:
                assert result.violation_type is not None
                break
        else:
            pytest.fail("Rate limit was not exceeded")
    
    @pytest.mark.asyncio
    async def test_ip_scoring(self, rate_engine):
        """Test IP scoring system"""
        ip_address = "192.168.1.100"
        
        # Check initial reputation
        reputation = rate_engine.ip_scoring.get_ip_reputation(ip_address)
        assert reputation.risk_level == RiskLevel.LOW
        assert reputation.score == 0.0
        
        # Add violations
        rate_engine.ip_scoring.update_ip_score(ip_address, {"user_agent": "test"}, ViolationType.RATE_LIMIT)
        rate_engine.ip_scoring.update_ip_score(ip_address, {"user_agent": "test"}, ViolationType.SUSPICIOUS_PATTERN)
        
        # Check updated reputation
        updated_reputation = rate_engine.ip_scoring.get_ip_reputation(ip_address)
        assert updated_reputation.score > 0.0
        assert len(updated_reputation.violations) > 0
    
    @pytest.mark.asyncio
    async def test_adaptive_rate_limiting(self, rate_engine):
        """Test adaptive rate limiting"""
        config = RateLimitConfig(
            name="adaptive_limiter",
            requests_per_second=10,
            burst_size=20,
            adaptive_enabled=True,
            ip_scoring_enabled=True
        )
        
        limiter = rate_engine.create_rate_limiter("adaptive", **config.__dict__)
        
        # Test with low-risk IP
        low_risk_data = {"ip_address": "192.168.1.1", "user_agent": "Mozilla/5.0"}
        result1 = await limiter.check_rate_limit("user1", low_risk_data)
        
        # Test with high-risk IP
        high_risk_data = {"ip_address": "192.168.1.100", "user_agent": "curl/7.68.0"}
        rate_engine.ip_scoring.update_ip_score("192.168.1.100", high_risk_data, ViolationType.SUSPICIOUS_PATTERN)
        result2 = await limiter.check_rate_limit("user2", high_risk_data)
        
        # High-risk IP should have lower limit
        assert result1.metadata["adaptive_limit"] >= result2.metadata["adaptive_limit"]


class TestThreatStream:
    """Test live threat stream"""
    
    @pytest.fixture
    async def threat_stream(self):
        """Create threat stream"""
        stream = LiveThreatStream()
        await stream.start()
        yield stream
        await stream.stop()
    
    @pytest.mark.asyncio
    async def test_threat_event_publishing(self, threat_stream):
        """Test threat event publishing"""
        threat_event = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            category=ThreatCategory.SECURITY_BREACH,
            title="Test Threat",
            description="Test threat event",
            source_ip="192.168.1.100"
        )
        
        await threat_stream.publish_threat_event(threat_event)
        
        # Check event was processed
        events = await threat_stream.event_buffer.get_recent_events(1)
        assert len(events) > 0
    
    @pytest.mark.asyncio
    async def test_attack_telemetry(self, threat_stream):
        """Test attack telemetry"""
        from app.monitoring.threat_stream import AttackTelemetry
        
        telemetry = AttackTelemetry(
            attack_type="brute_force",
            source_ip="192.168.1.100",
            target_endpoint="/api/login",
            request_count=50,
            failure_count=45
        )
        
        await threat_stream.publish_attack_telemetry(telemetry)
        
        # Check telemetry was processed
        events = await threat_stream.event_buffer.get_recent_events(1, 
                                                                event_type=type(telemetry))
        assert len(events) > 0
    
    @pytest.mark.asyncio
    async def test_threat_heatmaps(self, threat_stream):
        """Test threat heatmap generation"""
        # Add some threat data
        threat_event = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            category=ThreatCategory.THREAT_DETECTION,
            title="Test Threat",
            source_ip="192.168.1.100"
        )
        
        await threat_stream.publish_threat_event(threat_event)
        
        # Generate heatmaps
        heatmaps = threat_stream.get_heatmaps()
        
        assert "geographic" in heatmaps
        assert "temporal" in heatmaps
        assert "severity" in heatmaps
    
    @pytest.mark.asyncio
    async def test_stream_statistics(self, threat_stream):
        """Test stream statistics"""
        stats = threat_stream.get_stream_statistics()
        
        assert "enabled" in stats
        assert "websocket" in stats
        assert "event_buffer" in stats
        assert "stream_processor" in stats


class TestProcessGuard:
    """Test process guard"""
    
    @pytest.fixture
    async def process_guard(self):
        """Create process guard"""
        guard = ProcessGuard()
        await guard.start()
        yield guard
        await guard.stop()
    
    @pytest.mark.asyncio
    async def test_process_execution_monitoring(self, process_guard):
        """Test process execution monitoring"""
        # Test safe command
        result = await process_guard.execute_command("echo 'test'", user="testuser")
        assert result is not None
        
        # Check event was created
        events = process_guard.get_process_events(1)
        assert len(events) > 0
        assert events[0].command == "echo 'test'"
    
    @pytest.mark.asyncio
    async def test_suspicious_pattern_detection(self, process_guard):
        """Test suspicious pattern detection"""
        # Test suspicious command
        suspicious_cmd = "powershell -enc aW52aW5jLXRlc3Q="
        result = await process_guard.execute_command(suspicious_cmd, user="testuser")
        
        # Check threat was detected
        events = process_guard.get_process_events(1)
        assert len(events) > 0
        assert events[0].risk_level in [ProcessRiskLevel.HIGH, ProcessRiskLevel.CRITICAL]
        assert events[0].violation_type == ProcessViolationType.ENCODED_POWERSHELL
    
    @pytest.mark.asyncio
    async def test_async_process_monitoring(self, process_guard):
        """Test async process monitoring"""
        # Test async command
        result = await process_guard.execute_async_command("echo 'async test'", user="testuser")
        assert result is not None
        
        # Check event was created
        events = process_guard.get_process_events(1)
        assert len(events) > 0
        assert "async" in events[0].metadata.get("execution_method", "")
    
    def test_pattern_detector(self):
        """Test suspicious pattern detector"""
        from app.security.process_guard import SuspiciousPatternDetector
        
        detector = SuspiciousPatternDetector()
        
        # Test safe command
        risk_level, violation_type, description = detector.analyze_command(
            "echo 'safe command'", "echo", ["echo", "'safe command'"]
        )
        assert risk_level == ProcessRiskLevel.LOW
        assert violation_type is None
        
        # Test suspicious command
        risk_level, violation_type, description = detector.analyze_command(
            "powershell -enc aGVsbG8=", "powershell", ["-enc", "aGVsbG8="]
        )
        assert risk_level in [ProcessRiskLevel.HIGH, ProcessRiskLevel.CRITICAL]
        assert violation_type == ProcessViolationType.ENCODED_POWERSHELL


class TestTelemetryEngine:
    """Test telemetry engine"""
    
    @pytest.fixture
    async def telemetry_engine(self):
        """Create telemetry engine"""
        engine = TelemetryEngine()
        await engine.start()
        yield engine
        await engine.stop()
    
    @pytest.mark.asyncio
    async def test_request_telemetry(self, telemetry_engine):
        """Test request telemetry recording"""
        await telemetry_engine.record_request(
            method="POST",
            endpoint="/api/test",
            status_code=200,
            duration=0.1,
            size=1024,
            risk_level="low"
        )
        
        stats = telemetry_engine.get_statistics()
        assert stats["events_collected"] > 0
    
    @pytest.mark.asyncio
    async def test_security_telemetry(self, telemetry_engine):
        """Test security event telemetry"""
        await telemetry_engine.record_security_event(
            event_type="threat_detected",
            severity="high",
            source="192.168.1.100",
            risk_level="high"
        )
        
        stats = telemetry_engine.get_statistics()
        assert stats["events_collected"] > 0
    
    @pytest.mark.asyncio
    async def test_threat_telemetry(self, telemetry_engine):
        """Test threat telemetry"""
        await telemetry_engine.record_threat(
            threat_type="malware",
            severity="critical",
            category="malware_detection"
        )
        
        stats = telemetry_engine.get_statistics()
        assert stats["events_collected"] > 0
    
    @pytest.mark.asyncio
    async def test_prometheus_metrics(self, telemetry_engine):
        """Test Prometheus metrics generation"""
        # Record some data
        await telemetry_engine.record_request(
            method="GET", endpoint="/test", status_code=200,
            duration=0.05, size=512, risk_level="low"
        )
        
        metrics = telemetry_engine.get_prometheus_metrics()
        assert len(metrics) > 0
        assert "mary_v5_requests_total" in metrics
    
    @pytest.mark.asyncio
    async def test_telemetry_heatmaps(self, telemetry_engine):
        """Test telemetry heatmaps"""
        # Add threat data
        await telemetry_engine.record_threat(
            threat_type="ddos", severity="high", category="network_attack"
        )
        
        heatmaps = telemetry_engine.get_heatmaps()
        assert "geographic" in heatmaps
        assert "temporal" in heatmaps
        assert "severity" in heatmaps


class TestIncidentResponse:
    """Test incident response engine"""
    
    @pytest.fixture
    async def incident_engine(self):
        """Create incident response engine"""
        engine = IncidentResponseEngine()
        await engine.start()
        yield engine
        await engine.stop()
    
    @pytest.mark.asyncio
    async def test_incident_creation(self, incident_engine):
        """Test incident creation"""
        incident = await incident_engine.create_incident(
            title="Test Security Incident",
            description="Test incident for unit testing",
            source="security_monitor",
            additional_data={"source_ip": "192.168.1.100"}
        )
        
        assert incident is not None
        assert incident.title == "Test Security Incident"
        assert incident.status == IncidentStatus.NEW
        assert incident.severity in [IncidentSeverity.LOW, IncidentSeverity.MEDIUM, 
                                   IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_incident_classification(self, incident_engine):
        """Test incident classification"""
        incident = await incident_engine.create_incident(
            title="Critical Security Breach",
            description="Critical breach detected",
            source="security_monitor"
        )
        
        assert incident.category is not None
        assert incident.severity == IncidentSeverity.CRITICAL
        assert incident.escalation_level is not None
    
    @pytest.mark.asyncio
    async def test_incident_escalation(self, incident_engine):
        """Test incident escalation"""
        incident = await incident_engine.create_incident(
            title="High Priority Threat",
            description="High priority threat detected",
            source="security_monitor"
        )
        
        # Manual escalation
        success = await incident_engine.escalate_incident(incident.id)
        assert success is True
        
        # Check escalated status
        updated_incident = incident_engine.get_incident(incident.id)
        assert updated_incident.status == IncidentStatus.ESCALATED
    
    @pytest.mark.asyncio
    async def test_mitigation_actions(self, incident_engine):
        """Test mitigation actions"""
        incident = await incident_engine.create_incident(
            title="Test Incident",
            description="Test incident",
            source="test"
        )
        
        # Check mitigation actions were generated
        assert len(incident.mitigation_actions) > 0
    
    @pytest.mark.asyncio
    async def test_incident_statistics(self, incident_engine):
        """Test incident statistics"""
        # Create some incidents
        await incident_engine.create_incident("Test 1", "Description 1", "test")
        await incident_engine.create_incident("Test 2", "Description 2", "test")
        
        stats = incident_engine.get_statistics()
        assert stats["incidents_created"] >= 2
        assert "by_severity" in stats
        assert "by_category" in stats


class TestTaskManager:
    """Test secure async task manager"""
    
    @pytest.fixture
    async def task_manager(self):
        """Create task manager"""
        manager = SecureAsyncTaskManager()
        await manager.start()
        yield manager
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_task_submission(self, task_manager):
        """Test task submission"""
        async def test_task():
            await asyncio.sleep(0.1)
            return "task_result"
        
        task_id = await task_manager.submit_task(test_task())
        assert task_id is not None
        
        # Wait for completion
        await asyncio.sleep(0.2)
        
        result = await task_manager.get_task_result(task_id)
        assert result is not None
        assert result.status == TaskStatus.COMPLETED
        assert result.result == "task_result"
    
    @pytest.mark.asyncio
    async def test_task_failure_handling(self, task_manager):
        """Test task failure handling"""
        async def failing_task():
            raise ValueError("Test error")
        
        task_id = await task_manager.submit_task(failing_task())
        
        # Wait for completion
        await asyncio.sleep(0.2)
        
        result = await task_manager.get_task_result(task_id)
        assert result is not None
        assert result.status == TaskStatus.FAILED
        assert result.error is not None
    
    @pytest.mark.asyncio
    async def test_task_retry(self, task_manager):
        """Test task retry mechanism"""
        call_count = 0
        
        async def flaky_task():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Temporary failure")
            return "success_after_retry"
        
        task_id = await task_manager.submit_task(flaky_task(), max_retries=3)
        
        # Wait for completion
        await asyncio.sleep(1.0)
        
        result = await task_manager.get_task_result(task_id)
        assert result is not None
        assert result.status == TaskStatus.COMPLETED
        assert result.result == "success_after_retry"
        assert result.retries > 0
    
    @pytest.mark.asyncio
    async def test_task_cancellation(self, task_manager):
        """Test task cancellation"""
        async def long_task():
            await asyncio.sleep(10)
            return "should_not_complete"
        
        task_id = await task_manager.submit_task(long_task())
        
        # Cancel the task
        success = await task_manager.cancel_task(task_id)
        assert success is True
        
        result = await task_manager.get_task_result(task_id)
        assert result is not None
        assert result.status == TaskStatus.CANCELLED
    
    @pytest.mark.asyncio
    async def test_task_manager_statistics(self, task_manager):
        """Test task manager statistics"""
        # Submit some tasks
        async def quick_task():
            return "quick"
        
        for _ in range(5):
            await task_manager.submit_task(quick_task())
        
        await asyncio.sleep(0.5)
        
        stats = task_manager.get_statistics()
        assert stats["tasks_submitted"] >= 5
        assert "workers" in stats
        assert "queue" in stats


class TestSecurityCache:
    """Test security cache system"""
    
    @pytest.fixture
    async def cache_manager(self):
        """Create cache manager"""
        manager = SecurityCacheManager()
        await manager.start()
        yield manager
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_ioc_caching(self, cache_manager):
        """Test IOC caching"""
        # Set IOC
        success = await cache_manager.set_ioc(
            ioc_type="ip",
            value="192.168.1.100",
            reputation="malicious",
            confidence=0.9,
            source="threat_intel"
        )
        assert success is True
        
        # Get IOC
        ioc = await cache_manager.get_ioc("ip", "192.168.1.100")
        assert ioc is not None
        assert ioc.reputation == "malicious"
        assert ioc.confidence == 0.9
    
    @pytest.mark.asyncio
    async def test_ip_reputation_caching(self, cache_manager):
        """Test IP reputation caching"""
        reputation_data = {
            "score": 0.8,
            "risk_level": "high",
            "source": "reputation_service",
            "last_updated": datetime.utcnow().isoformat()
        }
        
        success = await cache_manager.set_ip_reputation("192.168.1.100", reputation_data)
        assert success is True
        
        cached_data = await cache_manager.get_ip_reputation("192.168.1.100")
        assert cached_data is not None
        assert cached_data["score"] == 0.8
        assert cached_data["risk_level"] == "high"
    
    @pytest.mark.asyncio
    async def test_threat_caching(self, cache_manager):
        """Test threat caching"""
        success = await cache_manager.set_threat(
            threat_id="threat_123",
            threat_type="malware",
            severity="critical",
            description="Test threat",
            source_ip="192.168.1.100"
        )
        assert success is True
        
        threat = await cache_manager.get_threat("threat_123")
        assert threat is not None
        assert threat.threat_type == "malware"
        assert threat.severity == "critical"
    
    @pytest.mark.asyncio
    async def test_cache_ttl(self, cache_manager):
        """Test cache TTL expiration"""
        # Set with short TTL
        success = await cache_manager.set_ip_reputation(
            "192.168.1.200",
            {"score": 0.5},
            ttl=1.0  # 1 second
        )
        assert success is True
        
        # Should be available immediately
        data = await cache_manager.get_ip_reputation("192.168.1.200")
        assert data is not None
        
        # Wait for expiration
        await asyncio.sleep(1.1)
        
        # Should be expired
        data = await cache_manager.get_ip_reputation("192.168.1.200")
        assert data is None
    
    @pytest.mark.asyncio
    async def test_cache_statistics(self, cache_manager):
        """Test cache statistics"""
        # Add some data
        await cache_manager.set_ioc("domain", "malicious.com", reputation="malicious")
        await cache_manager.set_ip_reputation("192.168.1.1", {"score": 0.3})
        
        stats = cache_manager.get_statistics()
        assert stats["enabled"] is True
        assert "cache_stats" in stats
        assert "global_stats" in stats
        assert stats["global_stats"]["total_hits"] >= 0
        assert stats["global_stats"]["total_misses"] >= 0


# ============================================
# Load and Stress Tests
# ============================================

class TestLoadPerformance:
    """Load and performance tests"""
    
    @pytest.mark.asyncio
    async def test_concurrent_rate_limiting(self):
        """Test concurrent rate limiting"""
        rate_engine = SecurityRateEngine()
        limiter = rate_engine.create_rate_limiter(
            "load_test",
            requests_per_second=100,
            burst_size=200,
            window_size=60
        )
        
        request_data = {"ip_address": "192.168.1.1", "user_agent": "load-test"}
        
        # Concurrent requests
        tasks = []
        for i in range(50):
            task = limiter.check_rate_limit(f"user_{i}", request_data)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # Most should pass
        passed = sum(1 for r in results if r.allowed)
        assert passed >= 40  # Allow some to be rate limited
    
    @pytest.mark.asyncio
    async def test_concurrent_task_processing(self):
        """Test concurrent task processing"""
        manager = SecureAsyncTaskManager()
        await manager.start()
        
        try:
            async def compute_task(value):
                await asyncio.sleep(0.01)
                return value * 2
            
            # Submit many tasks
            tasks = []
            for i in range(100):
                task_id = await manager.submit_task(compute_task(i))
                tasks.append(manager.get_task_result(task_id))
            
            # Wait for completion
            await asyncio.sleep(2.0)
            
            # Check results
            results = await asyncio.gather(*tasks)
            completed = sum(1 for r in results if r and r.status == TaskStatus.COMPLETED)
            assert completed >= 90  # Allow for some failures
        
        finally:
            await manager.stop()
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(self):
        """Test memory usage under load"""
        cache_manager = SecurityCacheManager()
        await cache_manager.start()
        
        try:
            # Add many cache entries
            tasks = []
            for i in range(1000):
                task = cache_manager.set_ip_reputation(
                    f"192.168.1.{i % 255}",
                    {"score": i % 100 / 100}
                )
                tasks.append(task)
            
            await asyncio.gather(*tasks)
            
            # Check memory usage
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            
            # Should not exceed reasonable limits
            assert memory_mb < 500  # 500MB limit
        
        finally:
            await cache_manager.stop()
    
    @pytest.mark.asyncio
    async def test_websocket_load(self):
        """Test WebSocket load"""
        stream = LiveThreatStream()
        await stream.start()
        
        try:
            # Simulate many threat events
            tasks = []
            for i in range(100):
                threat = ThreatEvent(
                    severity=ThreatSeverity.MEDIUM,
                    category=ThreatCategory.THREAT_DETECTION,
                    title=f"Load Test Threat {i}",
                    source_ip=f"192.168.1.{i % 255}"
                )
                task = stream.publish_threat_event(threat)
                tasks.append(task)
            
            await asyncio.gather(*tasks)
            
            # Check statistics
            stats = stream.get_stream_statistics()
            assert stats["stream_processor"]["events_processed"] >= 100
        
        finally:
            await stream.stop()


# ============================================
# Integration Tests
# ============================================

class TestSystemIntegration:
    """System integration tests"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_detection(self):
        """Test end-to-end threat detection flow"""
        # Initialize components
        rate_engine = SecurityRateEngine()
        stream = LiveThreatStream()
        telemetry = TelemetryEngine()
        incident_engine = IncidentResponseEngine()
        
        await stream.start()
        await telemetry.start()
        await incident_engine.start()
        
        try:
            # Simulate attack
            attacker_ip = "192.168.1.100"
            
            # 1. Rate limiting detects abuse
            limiter = rate_engine.create_rate_limiter("integration_test", 
                                                    requests_per_second=5, burst_size=10)
            request_data = {"ip_address": attacker_ip, "user_agent": "attack-bot"}
            
            # Exceed rate limit
            rate_violations = []
            for i in range(15):
                result = await limiter.check_rate_limit(f"attacker_{i}", request_data)
                if not result.allowed:
                    rate_violations.append(result)
            
            assert len(rate_violations) > 0
            
            # 2. Create threat event
            threat = ThreatEvent(
                severity=ThreatSeverity.HIGH,
                category=ThreatCategory.RATE_LIMITING,
                title="Rate Limiting Attack",
                description=f"Rate limit exceeded from {attacker_ip}",
                source_ip=attacker_ip
            )
            await stream.publish_threat_event(threat)
            
            # 3. Record telemetry
            await telemetry.record_security_event(
                event_type="rate_limit_violation",
                severity="high",
                source=attacker_ip,
                risk_level="high"
            )
            
            # 4. Create incident
            incident = await incident_engine.create_incident(
                title="Rate Limiting Attack Detected",
                description=f"Automated rate limiting attack from {attacker_ip}",
                source="rate_engine",
                additional_data={"source_ip": attacker_ip, "violations": len(rate_violations)}
            )
            
            assert incident is not None
            assert incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
            
        finally:
            await stream.stop()
            await telemetry.stop()
            await incident_engine.stop()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        """Test circuit breaker integration with other components"""
        # Create circuit breaker
        config = CircuitBreakerConfig(
            name="integration_test",
            failure_threshold=3,
            timeout=2.0
        )
        breaker = CircuitBreaker(config)
        
        # Create telemetry
        telemetry = TelemetryEngine()
        await telemetry.start()
        
        try:
            # Simulate failing service
            call_count = 0
            
            async def failing_service():
                nonlocal call_count
                call_count += 1
                if call_count < 5:
                    raise ConnectionError("Service unavailable")
                return "recovered"
            
            # Trigger failures
            for _ in range(4):
                try:
                    await breaker.call(failing_service)
                except ConnectionError:
                    pass
            
            # Circuit should be open
            assert breaker.get_state() == CircuitState.OPEN
            
            # Record telemetry
            await telemetry.record_security_event(
                event_type="circuit_breaker_open",
                severity="medium",
                source="integration_test",
                risk_level="medium"
            )
            
            # Wait for recovery
            await asyncio.sleep(2.1)
            
            # Should recover
            result = await breaker.call(failing_service)
            assert result == "recovered"
            
        finally:
            await telemetry.stop()


# ============================================
# Test Configuration
# ============================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Test configuration
pytest_plugins = []

# Configure pytest for async tests
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "asyncio: mark test to run with asyncio"
    )
    config.addinivalue_line(
        "markers", "load: mark test as load test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )


if __name__ == "__main__":
    # Run tests
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--asyncio-mode=auto",
        "-m", "not load"  # Skip load tests by default
    ])
