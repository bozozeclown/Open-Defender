#!/bin/bash
# scripts/validate-metrics.sh

set -e

ENVIRONMENT=${1:-development}

echo "Validating metrics configuration for environment: $ENVIRONMENT"

# Check if Prometheus is accessible
check_prometheus() {
    local prometheus_url=$1
    
    echo "Checking Prometheus at $prometheus_url"
    
    if curl -s "$prometheus_url/api/v1/targets" | grep -q "health"; then
        echo "✓ Prometheus is accessible"
        
        # Check targets
        curl -s "$prometheus_url/api/v1/targets" | jq '.data.activeTargets[] | {health: .health, labels: .labels}' > /tmp/prometheus_targets.json
        
        echo "Prometheus targets:"
        cat /tmp/prometheus_targets.json
        
        # Check for unhealthy targets
        unhealthy=$(cat /tmp/prometheus_targets.json | jq -r 'select(.health != "up")')
        if [ -n "$unhealthy" ]; then
            echo "⚠ Unhealthy targets found:"
            echo "$unhealthy"
        fi
    else
        echo "✗ Prometheus is not accessible"
        return 1
    fi
}

# Check metrics endpoints
check_metrics_endpoint() {
    local service_name=$1
    local metrics_url=$2
    local username=$3
    local password=$4
    
    echo "Checking metrics endpoint for $service_name at $metrics_url"
    
    if [ -n "$username" ] && [ -n "$password" ]; then
        response=$(curl -s -u "$username:$password" "$metrics_url")
    else
        response=$(curl -s "$metrics_url")
    fi
    
    if echo "$response" | grep -q "HELP"; then
        echo "✓ $service_name metrics endpoint is accessible"
        
        # Count metrics
        metric_count=$(echo "$response" | grep -c "^# HELP")
        echo "  Found $metric_count metrics"
        
        # Check for critical metrics
        critical_metrics=("http_requests_total" "db_connections_active" "events_processed_total")
        for metric in "${critical_metrics[@]}"; do
            if echo "$response" | grep -q "$metric"; then
                echo "  ✓ Found critical metric: $metric"
            else
                echo "  ✗ Missing critical metric: $metric"
            fi
        done
    else
        echo "✗ $service_name metrics endpoint is not accessible"
        return 1
    fi
}

# Validate based on environment
case $ENVIRONMENT in
    "development")
        echo "Validating development environment..."
        
        check_prometheus "http://localhost:9091"
        
        check_metrics_endpoint "security-monitoring" "http://localhost:9090/metrics" "admin" "admin"
        check_metrics_endpoint "postgres-exporter" "http://localhost:9187/metrics"
        check_metrics_endpoint "redis-exporter" "http://localhost:9121/metrics"
        check_metrics_endpoint "node-exporter" "http://localhost:9100/metrics"
        check_metrics_endpoint "cadvisor" "http://localhost:8080/metrics"
        ;;
        
    "production")
        echo "Validating production environment..."
        
        check_prometheus "http://prometheus:9090"
        
        # Get credentials from environment
        METRICS_USERNAME=${METRICS_USERNAME:-admin}
        METRICS_PASSWORD=${METRICS_PASSWORD:-admin}
        
        check_metrics_endpoint "security-monitoring" "http://security-monitoring:9090/metrics" "$METRICS_USERNAME" "$METRICS_PASSWORD"
        check_metrics_endpoint "postgres-exporter" "http://postgres-exporter:9187/metrics"
        check_metrics_endpoint "redis-exporter" "http://redis-exporter:9121/metrics"
        check_metrics_endpoint "node-exporter" "http://node-exporter:9100/metrics"
        check_metrics_endpoint "cadvisor" "http://cadvisor:8080/metrics"
        ;;
        
    *)
        echo "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

echo "Metrics validation completed successfully"