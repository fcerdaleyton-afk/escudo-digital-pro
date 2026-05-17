# MARY V5 SHIELD CORE - Complete Documentation

## 🛡️ Overview

MARY V5 SHIELD CORE is an enterprise-grade defensive cybersecurity platform that provides comprehensive protection, real-time monitoring, and zero-trust security architecture. This platform is designed specifically for defensive security operations with no offensive capabilities.

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Installation & Deployment](#installation--deployment)
4. [Configuration Guide](#configuration-guide)
5. [Security Features](#security-features)
6. [API Documentation](#api-documentation)
7. [Monitoring & Observability](#monitoring--observability)
8. [Testing Guide](#testing-guide)
9. [Troubleshooting](#troubleshooting)
10. [Performance Optimization](#performance-optimization)

---

## 🏗️ Architecture Overview

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MARY V5 SHIELD CORE                    │
├─────────────────────────────────────────────────────────────┤
│  API Layer                                                 │
│  ├── Health & Security Endpoints                          │
│  ├── Enterprise API Routes                                 │
│  └── WebSocket Real-time Interface                         │
├─────────────────────────────────────────────────────────────┤
│  Security Middleware Layer                                  │
│  ├── API Hardening (Anti-DDoS, Abuse Detection)            │
│  ├── Security Headers (HSTS, CSP, XSS Protection)          │
│  ├── Request Validation & Filtering                       │
│  └── Rate Limiting & Throttling                           │
├─────────────────────────────────────────────────────────────┤
│  Core Security Engine                                       │
│  ├── Threat Orchestration & Correlation                    │
│  ├── Event Processing Pipeline                             │
│  ├── Incident Management                                   │
│  └── Automated Mitigation Hooks                            │
├─────────────────────────────────────────────────────────────┤
│  Detection & Analysis Layer                                │
│  ├── Real-time Threat Detection                            │
│  ├── Windows Defender (Suspicious Activity)                │
│  ├── Threat Intelligence (IOC Management)                  │
│  └── Pattern Recognition                                  │
├─────────────────────────────────────────────────────────────┤
│  Monitoring & Alerting Layer                              │
│  ├── Live Alert System (WebSocket)                         │
│  ├── Real-time Dashboard                                   │
│  ├── SIEM Integration                                      │
│  └── Performance Metrics                                   │
├─────────────────────────────────────────────────────────────┤
│  Data & Audit Layer                                        │
│  ├── Structured Logging (JSON)                            │
│  ├── Audit Trail System                                    │
│  ├── Compliance Reporting                                  │
│  └── Data Retention Management                             │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure Layer                                       │
│  ├── Async Performance Optimizer                          │
│  ├── Redis Caching & Pub/Sub                             │
│  ├── Database Security & Encryption                       │
│  └── Memory Management                                    │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
User Request → Security Middleware → Threat Engine → Detection Systems
     ↓                    ↓                ↓              ↓
  Validation        Event Processing   Analysis       Alert Generation
     ↓                    ↓                ↓              ↓
Rate Limiting    Correlation      Windows        WebSocket Broadcast
     ↓                    ↓                ↓              ↓
  API Response   Incident Creation  Intel Feed     Dashboard Update
```

---

## 🔧 Core Components

### 1. Security Engine (`app/security/security_engine.py`)

**Purpose**: Central threat orchestration and event correlation

**Key Features**:
- Real-time event processing with async workers
- Advanced threat correlation patterns
- Incident lifecycle management
- Automated mitigation hooks
- WebSocket event broadcasting

**Configuration**:
```bash
SECURITY_ENGINE_ENABLED=true
SECURITY_ENGINE_WORKERS=4
```

### 2. Live Alert System (`app/monitoring/live_alerts.py`)

**Purpose**: Real-time alert management and distribution

**Key Features**:
- Priority-based alert queuing
- WebSocket real-time updates
- SIEM-compatible JSON payloads
- Alert acknowledgment and resolution
- Multi-channel alert distribution

**Configuration**:
```bash
LIVE_ALERTS_ENABLED=true
WEBSOCKET_PORT=8765
ALERT_QUEUE_SIZE=10000
```

### 3. Windows Defender (`app/detection/windows_defender.py`)

**Purpose**: Windows-specific threat detection (DEFENSIVE ONLY)

**Key Features**:
- Suspicious scheduled task analysis
- Registry autorun detection
- PowerShell command monitoring
- Startup folder persistence detection
- Windows WMI subscription analysis

**Configuration**:
```bash
WINDOWS_DEFENDER_ENABLED=true
WINDOWS_ANALYSIS_INTERVAL=300
```

### 4. Threat Intelligence (`app/security/threat_intelligence.py`)

**Purpose**: IOC management and reputation analysis

**Key Features**:
- Multi-source IOC ingestion
- Local cache with LRU eviction
- Offline mode support
- Reputation scoring system
- Automated feed updates

**Configuration**:
```bash
THREAT_INTEL_ENABLED=true
IOC_CACHE_SIZE=100000
THREAT_INTEL_OFFLINE_MODE=false
```

### 5. API Hardening (`app/middleware/api_hardening.py`)

**Purpose**: API protection and abuse detection

**Key Features**:
- Advanced DDoS protection
- Request validation and sanitization
- Abuse pattern detection
- Rate limiting with burst handling
- Malformed request detection

**Configuration**:
```bash
API_HARDENING_ENABLED=true
GLOBAL_RPS=100
IP_RPS=10
DDOS_THRESHOLD=1000
```

### 6. Security Headers (`app/middleware/security_headers.py`)

**Purpose**: HTTP security headers implementation

**Key Features**:
- HSTS with preload support
- Content Security Policy (CSP)
- X-Frame-Options protection
- Referrer and Permissions policies
- CSP violation handling

**Configuration**:
```bash
SECURITY_HEADERS_ENABLED=true
HSTS_ENABLED=true
CSP_ENABLED=true
```

### 7. Audit Trail (`app/core/audit_trail.py`)

**Purpose**: Comprehensive audit logging

**Key Features**:
- Structured JSON audit events
- Compliance tagging (GDPR, HIPAA, PCI-DSS)
- Risk scoring and correlation
- Long-term retention management
- Batch processing optimization

**Configuration**:
```bash
AUDIT_TRAIL_ENABLED=true
AUDIT_BATCH_SIZE=100
AUDIT_RETENTION_DAYS=2555
```

### 8. Async Performance (`app/core/async_performance.py`)

**Purpose**: Performance optimization and async processing

**Key Features**:
- Priority-based worker pools
- Async-safe caching with TTL
- Memory management and GC optimization
- Background task processing
- Performance metrics collection

**Configuration**:
```bash
ASYNC_PERFORMANCE_OPTIMIZER_ENABLED=true
ASYNC_WORKERS=10
ASYNC_CACHE_SIZE=10000
```

---

## 🚀 Installation & Deployment

### Prerequisites

- Python 3.11+
- Redis Server
- PostgreSQL (optional, for enhanced features)
- Docker & Docker Compose

### Quick Start

1. **Clone Repository**
```bash
git clone <repository-url>
cd escudo-digital
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Start Redis**
```bash
redis-server
```

5. **Run Application**
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Docker Deployment

1. **Build Image**
```bash
docker build -t mary-v5-shield-core .
```

2. **Run with Docker Compose**
```bash
docker-compose up -d
```

### Kubernetes Deployment

1. **Apply ConfigMap**
```bash
kubectl apply -f k8s/configmap.yaml
```

2. **Deploy Application**
```bash
kubectl apply -f k8s/deployment.yaml
```

3. **Expose Service**
```bash
kubectl apply -f k8s/service.yaml
```

---

## ⚙️ Configuration Guide

### Environment Variables

#### Core Configuration
```bash
# Application
APP_VERSION=2.0.0
ENVIRONMENT=production

# Security Engine
SECURITY_ENGINE_ENABLED=true
SECURITY_ENGINE_WORKERS=4

# Performance
ASYNC_PERFORMANCE_OPTIMIZER_ENABLED=true
ASYNC_WORKERS=10
ASYNC_CACHE_SIZE=10000
```

#### Security Configuration
```bash
# API Hardening
API_HARDENING_ENABLED=true
GLOBAL_RPS=100
IP_RPS=10
DDOS_THRESHOLD=1000
DDOS_BLOCK_DURATION=300

# Security Headers
SECURITY_HEADERS_ENABLED=true
HSTS_ENABLED=true
HSTS_MAX_AGE=31536000
CSP_ENABLED=true

# Threat Intelligence
THREAT_INTEL_ENABLED=true
IOC_CACHE_SIZE=100000
THREAT_INTEL_OFFLINE_MODE=false
```

#### Monitoring Configuration
```bash
# Live Alerts
LIVE_ALERTS_ENABLED=true
WEBSOCKET_PORT=8765
ALERT_QUEUE_SIZE=10000

# Audit Trail
AUDIT_TRAIL_ENABLED=true
AUDIT_BATCH_SIZE=100
AUDIT_RETENTION_DAYS=2555

# Logging
STRUCTURED_LOGGER_ENABLED=true
LOG_LEVEL=INFO
LOG_OUTPUT_FORMATS=json,console
```

#### Database Configuration
```bash
# Redis
REDIS_URL=redis://localhost:6379

# Database (optional)
DATABASE_URL=postgresql://user:pass@localhost/mary_v5
DATABASE_SECURITY_ENABLED=true
```

### Configuration Files

#### `app/config.py`
```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Application
    app_version: str = "2.0.0"
    environment: str = "production"
    
    # Security Engine
    security_engine_enabled: bool = True
    security_engine_workers: int = 4
    
    # API Configuration
    api_hardening_enabled: bool = True
    global_rps: int = 100
    ip_rps: int = 10
    
    # Performance
    async_performance_optimizer_enabled: bool = True
    async_workers: int = 10
    
    class Config:
        env_file = ".env"
```

---

## 🔒 Security Features

### Defense-in-Depth Architecture

1. **Network Layer**
   - DDoS protection with rate limiting
   - IP reputation filtering
   - Geographic blocking

2. **Application Layer**
   - Request validation and sanitization
   - SQL injection prevention
   - XSS protection headers

3. **Data Layer**
   - Field-level encryption
   - Database audit logging
   - Secure backup management

4. **Monitoring Layer**
   - Real-time threat detection
   - Behavioral analysis
   - Anomaly detection

### Zero-Trust Security Model

```
Request → Validation → Authentication → Authorization → Monitoring → Response
    ↓            ↓              ↓              ↓           ↓
  IP Check    Credential     Role-Based    Threat      Mitigation
  Filter      Verification   Permissions  Detection   Actions
```

### Compliance Frameworks

#### GDPR Compliance
- Data access logging
- Right to be forgotten
- Data retention policies
- Consent tracking

#### HIPAA Compliance
- PHI access monitoring
- Audit trail integrity
- User authentication logging

#### PCI-DSS Compliance
- Card data protection
- Network monitoring
- Security testing requirements

---

## 📡 API Documentation

### Health & Security Endpoints

#### `/health`
Basic health check
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "2.0.0",
  "environment": "production"
}
```

#### `/health/detailed`
Comprehensive health check with system metrics
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "system": {
    "cpu_percent": 25.5,
    "memory": {
      "total_gb": 16.0,
      "available_gb": 12.0,
      "percent": 25.0
    }
  }
}
```

#### `/health/security/status`
Comprehensive security status
```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "overall_status": "secure",
  "security_score": 95.5,
  "components": {
    "security_engine": {...},
    "live_alerts": {...},
    "threat_intelligence": {...}
  }
}
```

#### `/health/security/threats/live`
Live threat information
```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "total_threats": 15,
  "threats": [
    {
      "type": "alert",
      "severity": "medium",
      "title": "Suspicious login attempt",
      "timestamp": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### WebSocket API

#### Connection
```
ws://localhost:8765/ws
```

#### Message Format
```json
{
  "type": "alert",
  "timestamp": "2024-01-01T00:00:00Z",
  "alert": {
    "id": "alert_123",
    "priority": "high",
    "title": "Security Alert",
    "description": "Threat detected"
  }
}
```

---

## 📊 Monitoring & Observability

### Metrics Collection

#### System Metrics
- CPU and memory usage
- Request throughput
- Error rates
- Response times

#### Security Metrics
- Threat detection rate
- Alert volume
- Violation counts
- Risk scores

#### Performance Metrics
- Cache hit rates
- Queue sizes
- Worker utilization
- Task completion rates

### Dashboard Components

#### Real-time Alert Dashboard
- Live threat feed
- Alert priority distribution
- Recent security events
- System status indicators

#### Security Analytics Dashboard
- Threat trends over time
- Geographic threat distribution
- Attack vector analysis
- Compliance status

#### Performance Dashboard
- Response time histograms
- Throughput graphs
- Error rate tracking
- Resource utilization

### SIEM Integration

#### Log Format
```json
{
  "@timestamp": "2024-01-01T00:00:00.000Z",
  "event": {
    "kind": "alert",
    "category": ["security"],
    "severity": "high",
    "title": "Security Alert"
  },
  "source": {
    "ip": "192.168.1.100",
    "user": {
      "id": "user123"
    }
  },
  "tags": ["threat", "authentication"],
  "details": {...}
}
```

#### Supported SIEMs
- Splunk
- ELK Stack
- IBM QRadar
- Microsoft Sentinel

---

## 🧪 Testing Guide

### Test Categories

#### Unit Tests
- Individual component testing
- Mock external dependencies
- Fast feedback loop

#### Integration Tests
- Component interaction testing
- Database integration
- API endpoint testing

#### Security Tests
- Threat simulation
- Attack pattern testing
- Compliance validation

#### Performance Tests
- Load testing
- Stress testing
- Memory leak detection

### Running Tests

#### All Tests
```bash
pytest tests/ -v
```

#### Security Tests Only
```bash
pytest tests/security/ -v -m security
```

#### Performance Tests
```bash
pytest tests/performance/ -v -m performance
```

#### Coverage Report
```bash
pytest --cov=app tests/ --cov-report=html
```

### Test Configuration

#### `pytest.ini`
```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    asyncio: mark test to run with asyncio
    security: mark test as security test
    performance: mark test as performance test
```

---

## 🔧 Troubleshooting

### Common Issues

#### High Memory Usage
**Symptoms**: Memory usage exceeding 80%
**Solutions**:
- Check cache size configuration
- Review async worker count
- Enable memory optimization

#### Slow Response Times
**Symptoms**: API responses > 500ms
**Solutions**:
- Check worker pool utilization
- Review cache hit rates
- Optimize database queries

#### Alert System Not Working
**Symptoms**: No alerts being generated
**Solutions**:
- Verify WebSocket server status
- Check alert queue size
- Review alert configuration

#### Database Connection Issues
**Symptoms**: Database timeouts or connection errors
**Solutions**:
- Check database server status
- Verify connection pool settings
- Review query performance

### Debug Mode

#### Enable Debug Logging
```bash
LOG_LEVEL=DEBUG
STRUCTURED_LOGGER_ENABLED=true
```

#### Component-Specific Debugging
```bash
# Security Engine
SECURITY_ENGINE_ENABLED=true
SECURITY_ENGINE_DEBUG=true

# Performance Optimizer
ASYNC_PERFORMANCE_OPTIMIZER_ENABLED=true
ASYNC_DEBUG=true
```

### Health Check Scripts

#### System Health Check
```bash
#!/bin/bash
curl -f http://localhost:8000/health/detailed || exit 1
curl -f http://localhost:8000/health/security/status || exit 1
echo "System healthy"
```

#### Component Status Check
```python
import requests

def check_component_health():
    components = [
        "/health",
        "/health/security/status",
        "/health/detailed"
    ]
    
    for component in components:
        try:
            response = requests.get(f"http://localhost:8000{component}")
            if response.status_code != 200:
                print(f"❌ {component}: {response.status_code}")
            else:
                print(f"✅ {component}: OK")
        except Exception as e:
            print(f"❌ {component}: {e}")

if __name__ == "__main__":
    check_component_health()
```

---

## ⚡ Performance Optimization

### Async Processing

#### Worker Pool Configuration
```python
# High-throughput configuration
ASYNC_WORKERS=20
ASYNC_CACHE_SIZE=50000
```

#### Task Prioritization
```python
@async_performance_optimizer.submit_task(
    coro=critical_task(),
    priority=TaskPriority.CRITICAL
)
```

### Caching Strategy

#### Multi-Level Caching
1. **In-Memory Cache**: Fast access, limited size
2. **Redis Cache**: Distributed, larger capacity
3. **Database Cache**: Persistent, large datasets

#### Cache Optimization
```python
# TTL-based cache invalidation
@async_cache_result(ttl=300)  # 5 minutes
async def expensive_operation():
    return await compute_result()
```

### Memory Management

#### Garbage Collection Tuning
```python
# Aggressive GC for high-memory usage
MEMORY_THRESHOLD=0.8
GC_THRESHOLD=0.7
```

#### Memory Monitoring
```python
# Real-time memory tracking
memory_stats = async_performance_optimizer.memory_manager.get_memory_stats()
```

### Database Optimization

#### Connection Pooling
```python
# Database connection pool
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=30
```

#### Query Optimization
```python
# Use async database operations
async def get_user_async(user_id: str):
    return await database.fetch_one(
        "SELECT * FROM users WHERE id = ?", user_id
    )
```

---

## 📈 Production Readiness Checklist

### Security Checklist
- [ ] All security middleware enabled
- [ ] Rate limiting configured
- [ ] Security headers implemented
- [ ] Threat detection active
- [ ] Audit logging enabled
- [ ] Compliance requirements met

### Performance Checklist
- [ ] Async workers configured
- [ ] Caching enabled and tuned
- [ ] Memory optimization active
- [ ] Database pooling configured
- [ ] Monitoring endpoints working

### Monitoring Checklist
- [ ] Health endpoints responding
- [ ] Metrics collection active
- [ ] Alert system functional
- [ ] WebSocket server running
- [ ] SIEM integration configured

### Deployment Checklist
- [ ] Environment variables set
- [ ] Database migrations run
- [ ] SSL certificates configured
- [ ] Load balancer configured
- [ ] Backup systems in place

---

## 🎯 Best Practices

### Security Best Practices
1. **Principle of Least Privilege**: Minimal permissions required
2. **Defense in Depth**: Multiple security layers
3. **Zero Trust**: Never trust, always verify
4. **Continuous Monitoring**: Real-time threat detection
5. **Regular Updates**: Keep dependencies current

### Performance Best Practices
1. **Async Operations**: Use async/await consistently
2. **Connection Pooling**: Reuse database connections
3. **Caching Strategy**: Cache frequently accessed data
4. **Batch Processing**: Group operations for efficiency
5. **Resource Management**: Proper cleanup and disposal

### Operational Best Practices
1. **Structured Logging**: JSON format with correlation IDs
2. **Health Checks**: Comprehensive endpoint monitoring
3. **Graceful Degradation**: Fail safely when components fail
4. **Automated Testing**: Continuous integration testing
5. **Documentation**: Keep documentation current

---

## 📞 Support & Resources

### Documentation
- [API Reference](./api/README.md)
- [Configuration Guide](./docs/configuration.md)
- [Deployment Guide](./docs/deployment.md)
- [Troubleshooting Guide](./docs/troubleshooting.md)

### Community
- GitHub Issues: Report bugs and request features
- Discussion Forum: Community support and discussions
- Wiki: Community-maintained documentation

### Professional Support
- Enterprise Support: 24/7 support for enterprise customers
- Consulting Services: Custom implementation and optimization
- Training Programs: Security and operations training

---

## 📄 License

MARY V5 SHIELD CORE is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 🔄 Version History

### v2.0.0 (Current)
- Complete SHIELD CORE implementation
- Advanced security engine with threat orchestration
- Real-time alert system with WebSocket support
- Windows defender integration
- Threat intelligence module
- API hardening with anti-DDoS protection
- Comprehensive audit trail system
- Async performance optimization
- Full test coverage

### v1.0.0
- Basic security framework
- Simple logging and monitoring
- Limited threat detection

---

**MARY V5 SHIELD CORE** - Enterprise-grade defensive cybersecurity platform for modern applications. 🛡️
