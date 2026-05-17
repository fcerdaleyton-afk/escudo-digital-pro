#!/bin/bash
# MARY V5 SHIELD CORE v5.0 Enterprise - Health Check Script
# Comprehensive health monitoring for all services

set -euo pipefail

# ============================================
# Configuration
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_ROOT/logs/health-check.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Health check timeout
TIMEOUT=30
MAX_RETRIES=3

# ============================================
# Logging Functions
# ============================================
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# ============================================
# Health Check Functions
# ============================================
check_docker() {
    log_info "Checking Docker daemon..."
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        return 1
    fi
    
    log_info "Docker daemon is running"
    return 0
}

check_containers() {
    log_info "Checking container status..."
    
    local containers=("mary-v5-shield-core" "mary-v5-postgres" "mary-v5-redis" "mary-v5-nginx")
    local failed_containers=()
    
    for container in "${containers[@]}"; do
        if docker ps --filter "name=$container" --format "{{.Status}}" | grep -q "Up"; then
            log_info "✓ $container is running"
        else
            log_error "✗ $container is not running"
            failed_containers+=("$container")
        fi
    done
    
    if [[ ${#failed_containers[@]} -gt 0 ]]; then
        log_error "Failed containers: ${failed_containers[*]}"
        return 1
    fi
    
    return 0
}

check_application_health() {
    log_info "Checking application health..."
    
    local url="http://localhost:8000/health"
    local response
    local http_code
    
    response=$(curl -s -w "%{http_code}" -m "$TIMEOUT" "$url" 2>/dev/null)
    http_code="${response: -3}"
    
    if [[ "$http_code" == "200" ]]; then
        log_info "✓ Application health check passed (HTTP $http_code)"
        
        # Parse health response
        local health_data="${response%$http_code}"
        if command -v jq &> /dev/null; then
            local status=$(echo "$health_data" | jq -r '.status // "unknown"')
            local version=$(echo "$health_data" | jq -r '.version // "unknown"')
            local uptime=$(echo "$health_data" | jq -r '.uptime // "unknown"')
            
            log_info "  Status: $status"
            log_info "  Version: $version"
            log_info "  Uptime: $uptime"
        fi
        
        return 0
    else
        log_error "✗ Application health check failed (HTTP $http_code)"
        return 1
    fi
}

check_database_health() {
    log_info "Checking database health..."
    
    if ! docker ps --filter "name=mary-v5-postgres" --format "{{.Status}}" | grep -q "Up"; then
        log_error "Database container is not running"
        return 1
    fi
    
    # Check PostgreSQL connection
    local result
    result=$(docker exec mary-v5-postgres pg_isready -U maryuser 2>/dev/null)
    
    if [[ "$result" == "mary-v5 is accepting connections" ]]; then
        log_info "✓ Database is accepting connections"
        
        # Get database stats
        local db_stats=$(docker exec mary-v5-postgres psql -U maryuser -d maryv5 -c "
            SELECT 
                COUNT(*) as total_connections,
                COUNT(*) FILTER (WHERE state = 'active') as active_connections,
                (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active') as active_sessions
            FROM pg_stat_activity
        " 2>/dev/null | tail -n 1)
        
        if [[ -n "$db_stats" ]]; then
            log_info "  Database stats: $db_stats"
        fi
        
        return 0
    else
        log_error "✗ Database is not accepting connections"
        return 1
    fi
}

check_redis_health() {
    log_info "Checking Redis health..."
    
    if ! docker ps --filter "name=mary-v5-redis" --format "{{.Status}}" | grep -q "Up"; then
        log_error "Redis container is not running"
        return 1
    fi
    
    # Check Redis connection
    local result
    result=$(docker exec mary-v5-redis redis-cli ping 2>/dev/null)
    
    if [[ "$result" == "PONG" ]]; then
        log_info "✓ Redis is responding"
        
        # Get Redis stats
        local redis_info=$(docker exec mary-v5-redis redis-cli info server 2>/dev/null)
        local redis_version=$(echo "$redis_info" | grep "redis_version" | cut -d: -f2 | tr -d '\r')
        local uptime=$(echo "$redis_info" | grep "uptime_in_seconds" | cut -d: -f2 | tr -d '\r')
        local connected_clients=$(echo "$redis_info" | grep "connected_clients" | cut -d: -f2 | tr -d '\r')
        local used_memory=$(echo "$redis_info" | grep "used_memory_human" | cut -d: -f2 | tr -d '\r')
        
        log_info "  Version: $redis_version"
        log_info "  Uptime: $uptime seconds"
        log_info "  Connected clients: $connected_clients"
        log_info "  Memory usage: $used_memory"
        
        return 0
    else
        log_error "✗ Redis is not responding"
        return 1
    fi
}

check_nginx_health() {
    log_info "Checking Nginx health..."
    
    if ! docker ps --filter "name=mary-v5-nginx" --format "{{.Status}}" | grep -q "Up"; then
        log_error "Nginx container is not running"
        return 1
    fi
    
    # Check Nginx configuration
    if docker exec mary-v5-nginx nginx -t &> /dev/null; then
        log_info "✓ Nginx configuration is valid"
    else
        log_error "✗ Nginx configuration is invalid"
        return 1
    fi
    
    # Check Nginx status
    local url="http://localhost/health"
    local response
    local http_code
    
    response=$(curl -s -w "%{http_code}" -m "$TIMEOUT" "$url" 2>/dev/null)
    http_code="${response: -3}"
    
    if [[ "$http_code" == "200" ]]; then
        log_info "✓ Nginx is responding (HTTP $http_code)"
        return 0
    else
        log_error "✗ Nginx is not responding (HTTP $http_code)"
        return 1
    fi
}

check_monitoring_health() {
    log_info "Checking monitoring services..."
    
    local monitoring_services=("mary-v5-prometheus" "mary-v5-grafana")
    local failed_services=()
    
    for service in "${monitoring_services[@]}"; do
        if docker ps --filter "name=$service" --format "{{.Status}}" | grep -q "Up"; then
            log_info "✓ $service is running"
        else
            log_error "✗ $service is not running"
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_error "Failed monitoring services: ${failed_services[*]}"
        return 1
    fi
    
    # Check Prometheus
    if curl -s -f http://localhost:9090/-/healthy &> /dev/null; then
        log_info "✓ Prometheus is healthy"
    else
        log_error "✗ Prometheus is not healthy"
        return 1
    fi
    
    # Check Grafana
    if curl -s -f http://localhost:3000/api/health &> /dev/null; then
        log_info "✓ Grafana is healthy"
    else
        log_error "✗ Grafana is not healthy"
        return 1
    fi
    
    return 0
}

check_disk_space() {
    log_info "Checking disk space..."
    
    local threshold=80
    local df_output
    local usage_percent
    
    df_output=$(df -h / | tail -n 1)
    usage_percent=$(echo "$df_output" | awk '{print $5}' | sed 's/%//')
    
    if [[ $usage_percent -gt $threshold ]]; then
        log_error "✗ Disk usage is critical: ${usage_percent}% (threshold: ${threshold}%)"
        return 1
    else
        log_info "✓ Disk usage is OK: ${usage_percent}% (threshold: ${threshold}%)"
        return 0
    fi
}

check_memory_usage() {
    log_info "Checking memory usage..."
    
    local threshold=90
    local mem_usage
    local mem_percent
    
    mem_usage=$(free | grep Mem)
    mem_percent=$(echo "$mem_usage" | awk '{printf("%.0f", $3/$2 * 100.0)}')
    
    if (( $(echo "$mem_percent > $threshold" | bc -l) )); then
        log_error "✗ Memory usage is critical: ${mem_percent}% (threshold: ${threshold}%)"
        return 1
    else
        log_info "✓ Memory usage is OK: ${mem_percent}% (threshold: ${threshold}%)"
        return 0
    fi
}

check_cpu_usage() {
    log_info "Checking CPU usage..."
    
    local threshold=80
    local cpu_usage
    local cpu_percent
    
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    
    if (( $(echo "$cpu_usage > $threshold" | bc -l) )); then
        log_error "✗ CPU usage is critical: ${cpu_usage}% (threshold: ${threshold}%)"
        return 1
    else
        log_info "✓ CPU usage is OK: ${cpu_usage}% (threshold: ${threshold}%)"
        return 0
    fi
}

check_network_connectivity() {
    log_info "Checking network connectivity..."
    
    # Check external connectivity
    if curl -s --max-time 10 https://www.google.com > /dev/null; then
        log_info "✓ External connectivity is OK"
    else
        log_error "✗ External connectivity failed"
        return 1
    fi
    
    # Check internal connectivity
    if ping -c 1 -W 5 8.8.8.8 > /dev/null 2>&1; then
        log_info "✓ Internal connectivity is OK"
    else
        log_error "✗ Internal connectivity failed"
        return 1
    fi
    
    return 0
}

check_ssl_certificates() {
    log_info "Checking SSL certificates..."
    
    local cert_file="$PROJECT_ROOT/deploy/nginx/ssl/cert.pem"
    local key_file="$PROJECT_ROOT/deploy/nginx/ssl/key.pem"
    
    # Check certificate file exists
    if [[ ! -f "$cert_file" ]]; then
        log_error "✗ SSL certificate not found: $cert_file"
        return 1
    fi
    
    # Check private key file exists
    if [[ ! -f "$key_file" ]]; then
        log_error "✗ SSL private key not found: $key_file"
        return 1
    fi
    
    # Check certificate validity
    local cert_info
    cert_info=$(openssl x509 -in "$cert_file" -noout -dates 2>/dev/null)
    
    if [[ -n "$cert_info" ]]; then
        local not_after=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
        local expiry_date=$(date -d "$not_after" +%s)
        local current_date=$(date +%s)
        local days_until_expiry=$(( (expiry_date - current_date) / 86400 ))
        
        if [[ $days_until_expiry -lt 30 ]]; then
            log_error "✗ SSL certificate expires in $days_until_expiry days"
            return 1
        else
            log_info "✓ SSL certificate is valid (expires in $days_until_expiry days)"
        fi
    else
        log_error "✗ SSL certificate is invalid"
        return 1
    fi
    
    return 0
}

# ============================================
# Comprehensive Health Check
# ============================================
comprehensive_health_check() {
    log_info "Starting comprehensive health check..."
    
    local failed_checks=()
    local total_checks=0
    
    # Run all health checks
    local checks=(
        "check_docker"
        "check_containers"
        "check_application_health"
        "check_database_health"
        "check_redis_health"
        "check_nginx_health"
        "check_monitoring_health"
        "check_disk_space"
        "check_memory_usage"
        "check_cpu_usage"
        "check_network_connectivity"
        "check_ssl_certificates"
    )
    
    for check in "${checks[@]}"; do
        ((total_checks++))
        if ! $check; then
            failed_checks+=("$check")
        fi
    done
    
    # Summary
    local passed_checks=$((total_checks - ${#failed_checks[@]}))
    
    log_info "Health check summary:"
    log_info "  Total checks: $total_checks"
    log_info "  Passed checks: $passed_checks"
    log_info "  Failed checks: ${#failed_checks[@]}"
    
    if [[ ${#failed_checks[@]} -eq 0 ]]; then
        log_info "✓ All health checks passed!"
        return 0
    else
        log_error "✗ ${#failed_checks[@]} health checks failed:"
        for check in "${failed_checks[@]}"; do
            log_error "  - $check"
        done
        return 1
    fi
}

# ============================================
# Main Function
# ============================================
main() {
    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    case "${1:-comprehensive}" in
        comprehensive)
            comprehensive_health_check
            ;;
        docker)
            check_docker
            ;;
        containers)
            check_containers
            ;;
        application)
            check_application_health
            ;;
        database)
            check_database_health
            ;;
        redis)
            check_redis_health
            ;;
        nginx)
            check_nginx_health
            ;;
        monitoring)
            check_monitoring_health
            ;;
        resources)
            check_disk_space
            check_memory_usage
            check_cpu_usage
            ;;
        network)
            check_network_connectivity
            ;;
        ssl)
            check_ssl_certificates
            ;;
        *)
            echo "Usage: $0 {comprehensive|docker|containers|application|database|redis|nginx|monitoring|resources|network|ssl}"
            echo "  comprehensive  - Run all health checks (default)"
            echo "  docker         - Check Docker daemon"
            echo "  containers      - Check all containers"
            echo "  application     - Check application health"
            echo "  database        - Check database health"
            echo "  redis           - Check Redis health"
            echo "  nginx           - Check Nginx health"
            echo "  monitoring      - Check monitoring services"
            echo "  resources       - Check system resources"
            echo "  network         - Check network connectivity"
            echo "  ssl             - Check SSL certificates"
            exit 1
            ;;
    esac
}

# ============================================
# Script Entry Point
# ============================================
main "$@"
