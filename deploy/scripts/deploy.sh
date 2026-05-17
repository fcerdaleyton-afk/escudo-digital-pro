#!/bin/bash
# MARY V5 SHIELD CORE v5.0 Enterprise - Production Deployment Script
# Automated deployment with health checks and rollback capability

set -euo pipefail

# ============================================
# Configuration
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOY_DIR="$PROJECT_ROOT/deploy"
LOG_FILE="$PROJECT_ROOT/logs/deploy.log"
BACKUP_DIR="$PROJECT_ROOT/backups"
CONFIG_FILE="$PROJECT_ROOT/production.env"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
# Utility Functions
# ============================================
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log_info "Dependencies check passed"
}

check_configuration() {
    log_info "Checking configuration files..."
    
    # Check production environment file
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Production environment file not found: $CONFIG_FILE"
        log_info "Please create production.env based on production.env.example"
        exit 1
    fi
    
    # Check required environment variables
    local required_vars=("DB_PASSWORD" "JWT_SECRET" "REDIS_PASSWORD" "ENCRYPTION_KEY")
    for var in "${required_vars[@]}"; do
        if ! grep -q "^$var=" "$CONFIG_FILE"; then
            log_error "Required environment variable not set: $var"
            exit 1
        fi
    done
    
    # Check SSL certificates
    if [[ ! -f "$DEPLOY_DIR/nginx/ssl/cert.pem" ]]; then
        log_error "SSL certificate not found: $DEPLOY_DIR/nginx/ssl/cert.pem"
        exit 1
    fi
    
    if [[ ! -f "$DEPLOY_DIR/nginx/ssl/key.pem" ]]; then
        log_error "SSL private key not found: $DEPLOY_DIR/nginx/ssl/key.pem"
        exit 1
    fi
    
    log_info "Configuration check passed"
}

create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p "$PROJECT_ROOT/logs"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$PROJECT_ROOT/data/postgres"
    mkdir -p "$PROJECT_ROOT/data/redis"
    mkdir -p "$PROJECT_ROOT/data/prometheus"
    mkdir -p "$PROJECT_ROOT/data/grafana"
    mkdir -p "$PROJECT_ROOT/ssl"
    
    log_info "Directories created"
}

backup_current_deployment() {
    log_info "Backing up current deployment..."
    
    local backup_name="backup_$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    mkdir -p "$backup_path"
    
    # Backup current configuration
    if [[ -f "$PROJECT_ROOT/docker-compose.yml" ]]; then
        cp "$PROJECT_ROOT/docker-compose.yml" "$backup_path/"
    fi
    
    # Backup database
    if docker ps -q --filter "name=mary-v5-postgres" | grep -q .; then
        docker exec mary-v5-postgres pg_dump -U maryuser maryv5 > "$backup_path/database_backup.sql"
    fi
    
    # Backup Redis
    if docker ps -q --filter "name=mary-v5-redis" | grep -q .; then
        docker exec mary-v5-redis redis-cli --rdb > "$backup_path/redis_backup.rdb"
    fi
    
    log_info "Backup completed: $backup_name"
}

validate_health() {
    log_info "Validating service health..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Health check attempt $attempt/$max_attempts"
        
        # Check main application
        if curl -f http://localhost:8000/health &> /dev/null; then
            log_info "Main application is healthy"
            return 0
        fi
        
        # Check database
        if docker exec mary-v5-postgres pg_isready -U maryuser &> /dev/null; then
            log_info "Database is healthy"
        else
            log_warn "Database is not ready"
        fi
        
        # Check Redis
        if docker exec mary-v5-redis redis-cli ping &> /dev/null; then
            log_info "Redis is healthy"
        else
            log_warn "Redis is not ready"
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            log_error "Health check failed after $max_attempts attempts"
            return 1
        fi
        
        sleep 10
        ((attempt++))
    done
}

deploy_services() {
    log_info "Deploying services..."
    
    cd "$PROJECT_ROOT"
    
    # Stop existing services
    log_info "Stopping existing services..."
    docker-compose -f "$DEPLOY_DIR/docker/docker-compose.prod.yml" down
    
    # Pull latest images
    log_info "Pulling latest images..."
    docker-compose -f "$DEPLOY_DIR/docker/docker-compose.prod.yml" pull
    
    # Start services
    log_info "Starting services..."
    docker-compose -f "$DEPLOY_DIR/docker/docker-compose.prod.yml" up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Validate health
    if validate_health; then
        log_info "Deployment successful!"
        return 0
    else
        log_error "Deployment failed - services not healthy"
        return 1
    fi
}

rollback_deployment() {
    log_warn "Rolling back deployment..."
    
    cd "$PROJECT_ROOT"
    
    # Stop current services
    docker-compose -f "$DEPLOY_DIR/docker/docker-compose.prod.yml" down
    
    # Restore from backup
    local latest_backup=$(ls -t "$BACKUP_DIR" | head -n1)
    if [[ -n "$latest_backup" ]]; then
        log_info "Restoring from backup: $latest_backup"
        
        # Restore database
        if [[ -f "$BACKUP_DIR/$latest_backup/database_backup.sql" ]]; then
            docker-compose -f "$DEPLOY_DIR/docker/docker-compose.prod.yml" up -d postgres
            sleep 10
            docker exec -i mary-v5-postgres psql -U maryuser maryv5 < "$BACKUP_DIR/$latest_backup/database_backup.sql"
        fi
        
        # Restore Redis
        if [[ -f "$BACKUP_DIR/$latest_backup/redis_backup.rdb" ]]; then
            docker-compose -f "$DEPLOY_DIR/docker/docker-compose.prod.yml" up -d redis
            sleep 5
            docker cp "$BACKUP_DIR/$latest_backup/redis_backup.rdb" mary-v5-redis:/data/dump.rdb
            docker restart mary-v5-redis
        fi
        
        # Start all services
        docker-compose -f "$DEPLOY_DIR/docker/docker-compose.prod.yml" up -d
        
        log_info "Rollback completed"
    else
        log_error "No backup found for rollback"
        exit 1
    fi
}

cleanup() {
    log_info "Cleaning up..."
    
    # Remove unused Docker images
    docker image prune -f
    
    # Remove unused volumes
    docker volume prune -f
    
    # Clean old logs (keep last 7 days)
    find "$PROJECT_ROOT/logs" -name "*.log" -mtime +7 -delete
    
    log_info "Cleanup completed"
}

send_notification() {
    local status=$1
    local message=$2
    
    # Send email notification (if configured)
    if [[ -n "${EMAIL_SMTP_HOST:-}" ]]; then
        echo "$message" | mail -s "MARY V5 Deployment $status" "${EMAIL_RECIPIENT:-admin@escudo-digital.com}"
    fi
    
    # Send Slack notification (if configured)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"MARY V5 Deployment $status: $message\"}" \
            "$SLACK_WEBHOOK_URL"
    fi
}

# ============================================
# Main Deployment Function
# ============================================
main() {
    log_info "Starting MARY V5 SHIELD CORE deployment..."
    
    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    # Pre-deployment checks
    check_dependencies
    check_configuration
    create_directories
    
    # Backup current deployment
    backup_current_deployment
    
    # Deploy services
    if deploy_services; then
        log_info "Deployment completed successfully!"
        send_notification "SUCCESS" "MARY V5 SHIELD CORE has been deployed successfully"
        
        # Cleanup
        cleanup
        
        log_info "Deployment process completed successfully"
        exit 0
    else
        log_error "Deployment failed!"
        
        # Rollback on failure
        if [[ "${ROLLBACK_ON_FAILURE:-true}" == "true" ]]; then
            log_info "Initiating rollback..."
            rollback_deployment
        fi
        
        send_notification "FAILURE" "MARY V5 SHIELD CORE deployment failed"
        
        log_error "Deployment process failed"
        exit 1
    fi
}

# ============================================
# Script Entry Point
# ============================================
case "${1:-deploy}" in
    deploy)
        main
        ;;
    rollback)
        rollback_deployment
        ;;
    health)
        validate_health
        ;;
    cleanup)
        cleanup
        ;;
    backup)
        backup_current_deployment
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|health|cleanup|backup}"
        echo "  deploy  - Deploy the application (default)"
        echo "  rollback - Rollback to previous deployment"
        echo "  health   - Check service health"
        echo "  cleanup  - Clean up unused resources"
        echo "  backup   - Backup current deployment"
        exit 1
        ;;
esac
