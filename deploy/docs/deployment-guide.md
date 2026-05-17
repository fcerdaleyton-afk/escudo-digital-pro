# MARY V5 SHIELD CORE v5.0 Enterprise - Deployment Guide

## 🚀 **PRODUCTION DEPLOYMENT GUIDE**

### **Version**: 5.0.0 Enterprise  
### **Created**: 2026-05-12  
### **Status**: Production Ready

---

## 📋 **TABLE OF CONTENTS**

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Configuration](#configuration)
4. [Deployment Steps](#deployment-steps)
5. [Health Checks](#health-checks)
6. [Monitoring](#monitoring)
7. [Backup and Recovery](#backup-and-recovery)
8. [Troubleshooting](#troubleshooting)
9. [Security Considerations](#security-considerations)
10. [Maintenance](#maintenance)

---

## 🔧 **PREREQUISITES**

### **🖥️ System Requirements**
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **CPU**: 8+ cores (16+ recommended)
- **RAM**: 16GB+ (32GB+ recommended)
- **Storage**: 500GB+ SSD (1TB+ recommended)
- **Network**: 1Gbps+ (10Gbps+ recommended)

### **📦 Software Requirements**
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Git**: 2.25+
- **OpenSSL**: 1.1.1+
- **Curl**: Latest version
- **Bash**: 4.0+

### **🔐 Security Requirements**
- **SSL Certificates**: Valid certificates for production
- **Firewall**: Proper firewall configuration
- **Access Control**: Proper user permissions
- **Secrets Management**: Secure secret storage

---

## 🌍 **ENVIRONMENT SETUP**

### **📁 Directory Structure**
```bash
# Create deployment directory structure
mkdir -p /opt/mary-v5/{deploy,logs,data,backups,ssl}
cd /opt/mary-v5

# Clone repository
git clone https://github.com/escudo-digital/mary-v5-shield-core.git .

# Set permissions
chmod 755 /opt/mary-v5
chmod 700 /opt/mary-v5/ssl
chmod 755 /opt/mary-v5/deploy/scripts/*.sh
```

### **🔧 Environment Variables**
```bash
# Copy environment template
cp production.env.example production.env

# Edit environment file
nano production.env
```

### **📝 Required Environment Variables**
```bash
# Database Configuration
DB_PASSWORD=your_secure_db_password
DATABASE_URL=postgresql://maryuser:your_secure_db_password@postgres:5432/maryv5

# JWT Configuration
JWT_SECRET=your_secure_jwt_secret_at_least_32_characters_long

# Redis Configuration
REDIS_PASSWORD=your_secure_redis_password

# Encryption Configuration
ENCRYPTION_KEY=your_secure_encryption_key

# Monitoring Configuration
GRAFANA_USER=admin
GRAFANA_PASSWORD=your_secure_grafana_password

# SSL Configuration
SSL_CERT_PATH=/opt/mary-v5/ssl/cert.pem
SSL_KEY_PATH=/opt/mary-v5/ssl/key.pem
```

---

## ⚙️ **CONFIGURATION**

### **🔐 SSL Certificate Setup**
```bash
# Create SSL directory
mkdir -p /opt/mary-v5/ssl

# Copy your certificates
cp your-cert.pem /opt/mary-v5/ssl/cert.pem
cp your-key.pem /opt/mary-v5/ssl/key.pem
cp your-ca.pem /opt/mary-v5/ssl/ca.pem

# Set proper permissions
chmod 600 /opt/mary-v5/ssl/*.pem
chmod 644 /opt/mary-v5/ssl/ca.pem
```

### **🐳 Docker Configuration**
```bash
# Test Docker installation
docker --version
docker-compose --version

# Configure Docker daemon
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group
sudo usermod -aG docker $USER
```

### **🌐 Network Configuration**
```bash
# Configure firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Configure sysctl for performance
echo 'net.core.somaxconn = 65535' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_max_syn_backlog = 65535' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## 🚀 **DEPLOYMENT STEPS**

### **📋 Pre-Deployment Checklist**
- [ ] System requirements met
- [ ] Environment variables configured
- [ ] SSL certificates in place
- [ ] Firewall configured
- [ ] Docker installed and running
- [ ] Backup strategy in place
- [ ] Monitoring configured

### **🔄 Step 1: Prepare Environment**
```bash
# Navigate to deployment directory
cd /opt/mary-v5

# Create necessary directories
mkdir -p logs data/{postgres,redis,prometheus,grafana}

# Set permissions
chown -R $USER:$USER /opt/mary-v5
chmod 755 /opt/mary-v5/deploy/scripts/*.sh
```

### **🔄 Step 2: Validate Configuration**
```bash
# Check configuration
./deploy/scripts/deploy.sh health

# Validate environment
./deploy/scripts/health-check.sh comprehensive
```

### **🔄 Step 3: Deploy Services**
```bash
# Deploy application
./deploy/scripts/deploy.sh deploy

# Monitor deployment
docker-compose -f deploy/docker/docker-compose.prod.yml logs -f
```

### **🔄 Step 4: Verify Deployment**
```bash
# Check service health
./deploy/scripts/health-check.sh comprehensive

# Test application endpoints
curl -f http://localhost:8000/health
curl -f https://your-domain.com/health
curl -f https://api.your-domain.com/health
```

### **🔄 Step 5: Configure Monitoring**
```bash
# Access Grafana
# URL: https://your-domain.com:3000
# Username: admin
# Password: from environment variables

# Access Prometheus
# URL: http://localhost:9090
# Or: https://your-domain.com:9090 (if configured)
```

---

## 💚 **HEALTH CHECKS**

### **🔍 Application Health**
```bash
# Check application health
curl -f http://localhost:8000/health

# Check detailed health
curl -f http://localhost:8000/health/detailed

# Check API health
curl -f http://localhost:8000/api/health
```

### **🔍 Database Health**
```bash
# Check PostgreSQL
docker exec mary-v5-postgres pg_isready -U maryuser

# Check database connections
docker exec mary-v5-postgres psql -U maryuser -d maryv5 -c "SELECT COUNT(*) FROM pg_stat_activity;"
```

### **🔍 Redis Health**
```bash
# Check Redis
docker exec mary-v5-redis redis-cli ping

# Check Redis info
docker exec mary-v5-redis redis-cli info server
```

### **🔍 System Health**
```bash
# Comprehensive health check
./deploy/scripts/health-check.sh comprehensive

# Individual checks
./deploy/scripts/health-check.sh containers
./deploy/scripts/health-check.sh resources
./deploy/scripts/health-check.sh network
```

---

## 📊 **MONITORING**

### **📈 Prometheus Metrics**
- **URL**: http://localhost:9090
- **Key Metrics**:
  - Application performance
  - Security events
  - Database metrics
  - System resources
  - Container health

### **📊 Grafana Dashboards**
- **URL**: https://your-domain.com:3000
- **Dashboards**:
  - System Overview
  - Security Metrics
  - Performance Metrics
  - Database Performance
  - Container Health

### **🚨 Alerting**
- **AlertManager**: http://localhost:9093
- **Alert Channels**:
  - Email notifications
  - Slack notifications
  - PagerDuty integration
  - Webhook notifications

---

## 💾 **BACKUP AND RECOVERY**

### **🔄 Automated Backups**
```bash
# Run backup manually
python backup_automation.py daily

# Check backup status
./deploy/scripts/backup.sh status

# List backups
ls -la /opt/mary-v5/backups/
```

### **🔄 Backup Configuration**
```yaml
# backup_config.yaml
backup:
  enabled: true
  encryption: true
  validation: true

schedule:
  daily: "0 2 * * *"
  weekly: "0 1 * * 0"
  monthly: "0 0 1 * *"

retention:
  daily: 30
  weekly: 12
  monthly: 12
```

### **🔄 Recovery Procedures**
```bash
# Restore from backup
python restore_validation.py daily database

# Rollback deployment
./deploy/scripts/deploy.sh rollback

# Verify restore
./deploy/scripts/health-check.sh comprehensive
```

---

## 🔧 **TROUBLESHOOTING**

### **🐛 Common Issues**

#### **Application Not Starting**
```bash
# Check logs
docker-compose logs mary-v5-shield

# Check configuration
./deploy/scripts/health-check.sh application

# Restart services
docker-compose restart mary-v5-shield
```

#### **Database Connection Issues**
```bash
# Check database status
docker exec mary-v5-postgres pg_isready -U maryuser

# Check database logs
docker logs mary-v5-postgres

# Restart database
docker-compose restart postgres
```

#### **Redis Connection Issues**
```bash
# Check Redis status
docker exec mary-v5-redis redis-cli ping

# Check Redis logs
docker logs mary-v5-redis

# Restart Redis
docker-compose restart redis
```

#### **SSL Certificate Issues**
```bash
# Check certificate validity
openssl x509 -in /opt/mary-v5/ssl/cert.pem -noout -dates

# Check certificate chain
openssl verify -CAfile /opt/mary-v5/ssl/ca.pem /opt/mary-v5/ssl/cert.pem

# Reload Nginx
docker-compose restart nginx
```

### **📊 Performance Issues**
```bash
# Check system resources
./deploy/scripts/health-check.sh resources

# Check application performance
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/health

# Check database performance
docker exec mary-v5-postgres psql -U maryuser -d maryv5 -c "SELECT * FROM pg_stat_activity;"
```

---

## 🔒 **SECURITY CONSIDERATIONS**

### **🛡️ Security Hardening**
- **Network Security**: Firewall configuration, network segmentation
- **Application Security**: Input validation, rate limiting, encryption
- **Container Security**: Non-root execution, read-only filesystems
- **Data Security**: Encryption at rest and in transit
- **Access Control**: Role-based access, least privilege

### **🔐 Security Best Practices**
- **Regular Updates**: Keep all components updated
- **Security Scanning**: Regular vulnerability scanning
- **Audit Logging**: Comprehensive audit trail
- **Incident Response**: Security incident response plan
- **Compliance**: Regular compliance audits

### **🔍 Security Monitoring**
- **Threat Detection**: Real-time threat monitoring
- **Anomaly Detection**: Behavioral analysis
- **Security Metrics**: Security performance indicators
- **Alerting**: Security event alerting
- **Reporting**: Security compliance reporting

---

## 🔧 **MAINTENANCE**

### **📅 Regular Maintenance Tasks**

#### **Daily**
- [ ] Check system health
- [ ] Review security logs
- [ ] Monitor performance metrics
- [ ] Verify backup completion
- [ ] Check SSL certificates

#### **Weekly**
- [ ] Update security patches
- [ ] Review system logs
- [ ] Clean up old logs
- [ ] Test backup restoration
- [ ] Update monitoring rules

#### **Monthly**
- [ ] Apply security updates
- [ ] Review user access
- [ ] Update documentation
- [ ] Performance tuning
- [ ] Security audit

#### **Quarterly**
- [ ] Major version updates
- [ ] Security assessment
- [ ] Disaster recovery testing
- [ ] Capacity planning
- [ ] Compliance review

### **🔄 Update Procedures**
```bash
# Update application
git pull origin main
docker-compose -f deploy/docker/docker-compose.prod.yml pull
docker-compose -f deploy/docker/docker-compose.prod.yml up -d

# Update monitoring
docker-compose -f deploy/docker/docker-compose.prod.yml restart prometheus grafana

# Verify update
./deploy/scripts/health-check.sh comprehensive
```

### **📊 Performance Tuning**
```bash
# Monitor performance metrics
./deploy/scripts/health-check.sh performance

# Tune database parameters
docker exec mary-v5-postgres psql -U maryuser -d maryv5 -c "ALTER SYSTEM SET shared_buffers = '256MB';"

# Tune Redis settings
docker exec mary-v5-redis redis-cli CONFIG SET maxmemory 512mb
```

---

## 🎯 **CONCLUSION**

### **✅ Deployment Success**
The MARY V5 SHIELD CORE v5.0 Enterprise platform is now deployed and ready for production use.

### **🔑 Key Points**
- **Health Monitoring**: Comprehensive health checks in place
- **Security**: Enterprise-grade security implemented
- **Performance**: Optimized for high performance
- **Monitoring**: Real-time monitoring and alerting
- **Backup**: Automated backup and recovery
- **Documentation**: Complete documentation available

### **📞 Support**
- **Documentation**: `/deploy/docs/`
- **Runbook**: `/deploy/docs/runbook.md`
- **Troubleshooting**: `/deploy/docs/troubleshooting.md`
- **Support Team**: support@escudo-digital.com

---

## 📞 **CONTACT INFORMATION**

### **🔧 Technical Support**
- **Email**: support@escudo-digital.com
- **Phone**: +1-800-MARY-V5
- **Slack**: #mary-v5-support
- **Documentation**: https://docs.escudo-digital.com

### **🚨 Emergency Support**
- **Email**: emergency@escudo-digital.com
- **Phone**: +1-800-EMERGENCY
- **PagerDuty**: MARY-V5-EMERGENCY

---

*Deployment Guide Generated: 2026-05-12*  
*Version: 5.0.0 Enterprise*  
*Status: Production Ready*
