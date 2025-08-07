#!/bin/bash
# scripts/validate-network.sh

set -e

ENVIRONMENT=${1:-development}

echo "Validating network configuration for environment: $ENVIRONMENT"

# Check if required services are running
check_service() {
    local service_name=$1
    local container_name=$2
    local port=$3
    
    echo "Checking service: $service_name"
    
    if docker ps --format "table {{.Names}}" | grep -q "$container_name"; then
        echo "✓ Container $container_name is running"
        
        if nc -z localhost $port; then
            echo "✓ Port $port is accessible"
        else
            echo "✗ Port $port is not accessible"
            return 1
        fi
    else
        echo "✗ Container $container_name is not running"
        return 1
    fi
}

# Check service connectivity
check_connectivity() {
    local from_service=$1
    local to_service=$2
    local port=$3
    
    echo "Checking connectivity from $from_service to $to_service:$port"
    
    if docker exec $from_service nc -z $to_service $port; then
        echo "✓ $from_service can connect to $to_service:$port"
    else
        echo "✗ $from_service cannot connect to $to_service:$port"
        return 1
    fi
}

# Validate based on environment
case $ENVIRONMENT in
    "development")
        echo "Validating development environment..."
        
        # Check if all services are running
        check_service "PostgreSQL" "postgres" 5432
        check_service "Redis" "redis" 6379
        check_service "Security Monitoring" "security-monitoring" 8000
        check_service "Prometheus" "prometheus" 9091
        check_service "Grafana" "grafana" 3000
        check_service "Jaeger" "jaeger" 16686
        
        # Check service connectivity
        check_connectivity "security-monitoring" "postgres" 5432
        check_connectivity "security-monitoring" "redis" 6379
        check_connectivity "prometheus" "security-monitoring" 9090
        ;;
        
    "production")
        echo "Validating production environment..."
        
        # Check Kubernetes services
        kubectl get services -n security-monitoring
        
        # Check pod status
        kubectl get pods -n security-monitoring
        
        # Check service endpoints
        kubectl get endpoints -n security-monitoring
        ;;
        
    *)
        echo "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

echo "Network validation completed successfully"