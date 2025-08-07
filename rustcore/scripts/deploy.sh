#!/bin/bash

set -e

# Configuration
ENVIRONMENT=${1:-production}
COMPOSE_FILE="docker-compose.${ENVIRONMENT}.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    command -v docker >/dev/null 2>&1 || error "Docker is not installed"
    command -v docker-compose >/dev/null 2>&1 || error "Docker Compose is not installed"
    
    log "Prerequisites check passed"
}

# Create necessary directories
setup_directories() {
    log "Setting up directories..."
    
    mkdir -p logs
    mkdir -p config
    mkdir -p monitoring/grafana/dashboards
    mkdir -p monitoring/grafana/datasources
    mkdir -p data/postgres
    mkdir -p data/redis
    
    log "Directories created"
}

# Generate production configuration
generate_config() {
    log "Generating production configuration..."
    
    cat > .env.production << EOF
# Database
DATABASE_URL=postgres://postgres:${POSTGRES_PASSWORD}@db:5432/security_monitoring
DB_MAX_CONNECTIONS=20

# Analytics
EVENT_BUFFER_SIZE=50000
PORT_SCAN_THRESHOLD=100
DATA_EXFILTRATION_THRESHOLD=52428800
SUSPICIOUS_PROCESSES=powershell.exe,cmd.exe,wscript.exe,cscript.exe,rundll32.exe,regsvr32.exe
SYSTEM_METRICS_INTERVAL=30

# API
GRAPHQL_ENDPOINT=0.0.0.0:8000
JWT_SECRET=${JWT_SECRET}
CORS_ORIGINS=https://yourdomain.com

# Collaboration
WEBSOCKET_ENDPOINT=0.0.0.0:8001
REDIS_URL=redis://redis:6379

# Observability
RUST_LOG=info
JAEGER_ENDPOINT=jaeger:6831
METRICS_ENDPOINT=0.0.0.0:9090

# Production specific
ENVIRONMENT=production
ENABLE_METRICS=true
ENABLE_TRACING=true
EOF

    log "Production configuration generated"
}

# Build and deploy
deploy() {
    log "Building and deploying services..."
    
    # Pull latest images
    docker-compose -f $COMPOSE_FILE pull
    
    # Build application
    docker-compose -f $COMPOSE_FILE build --no-cache
    
    # Stop existing services
    docker-compose -f $COMPOSE_FILE down
    
    # Start services
    docker-compose -f $COMPOSE_FILE up -d
    
    # Wait for services to be healthy
    log "Waiting for services to be healthy..."
    sleep 30
    
    # Run database migrations
    docker-compose -f $COMPOSE_FILE exec -T app /usr/local/bin/exploit_detector --migrate
    
    log "Deployment completed successfully"
}

# Health check
health_check() {
    log "Performing health check..."
    
    # Check API health
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        log "API health check passed"
    else
        error "API health check failed"
    fi
    
    # Check metrics endpoint
    if curl -f http://localhost:9090/metrics > /dev/null 2>&1; then
        log "Metrics endpoint health check passed"
    else
        error "Metrics endpoint health check failed"
    fi
    
    log "All health checks passed"
}

# Main deployment process
main() {
    log "Starting deployment for environment: $ENVIRONMENT"
    
    check_prerequisites
    setup_directories
    generate_config
    deploy
    health_check
    
    log "Deployment completed successfully!"
    log "Access points:"
    log "  - GraphQL API: http://localhost:8000"
    log "  - WebSocket: ws://localhost:8001"
    log "  - Metrics: http://localhost:9090"
    log "  - Grafana: http://localhost:3000"
    log "  - Jaeger: http://localhost:16686"
}

# Run main function
main "$@"