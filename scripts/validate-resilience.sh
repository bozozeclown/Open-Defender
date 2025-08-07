#!/bin/bash
# scripts/validate-resilience.sh

set -e

ENVIRONMENT=${1:-development}

echo "Validating resilience configuration for environment: $ENVIRONMENT"

# Check if application is running
check_application_health() {
    echo "Checking application health..."
    
    if curl -s http://localhost:8000/health | jq -e '.status == "Healthy"' > /dev/null; then
        echo "✓ Application is healthy"
    else
        echo "⚠ Application health check failed or degraded"
        return 1
    fi
}

# Test circuit breaker functionality
test_circuit_breaker() {
    echo "Testing circuit breaker functionality..."
    
    # This would typically involve testing with a mock service that can fail
    echo "Note: Circuit breaker testing requires integration tests"
    
    # Check circuit breaker metrics
    if curl -s http://localhost:8000/health | jq -e '.circuit_breakers | length > 0' > /dev/null; then
        echo "✓ Circuit breaker metrics are available"
    else
        echo "⚠ No circuit breaker metrics found"
    fi
}

# Test retry mechanism
test_retry_mechanism() {
    echo "Testing retry mechanism..."
    
    # This would typically involve testing with a flaky service
    echo "Note: Retry mechanism testing requires integration tests"
    
    # Check for retry-related metrics
    if curl -s http://localhost:9090/metrics | grep -q "retry_attempts_total"; then
        echo "✓ Retry metrics are available"
    else
        echo "⚠ No retry metrics found"
    fi
}

# Test rate limiting
test_rate_limiting() {
    echo "Testing rate limiting..."
    
    # Make rapid requests to trigger rate limiting
    local count=0
    for i in {1..110}; do
        if curl -s http://localhost:8000/health -o /dev/null -w "%{http_code}" | grep -q "429"; then
            echo "✓ Rate limiting is working (got 429 after $count requests)"
            return
        fi
        count=$((count + 1))
        sleep 0.01
    done
    
    echo "⚠ Rate limiting may not be working properly"
}

# Test timeout handling
test_timeout_handling() {
    echo "Testing timeout handling..."
    
    # This would typically involve testing with a slow endpoint
    echo "Note: Timeout testing requires integration tests"
    
    # Check for timeout metrics
    if curl -s http://localhost:9090/metrics | grep -q "http_request_duration_seconds"; then
        echo "✓ Request duration metrics are available"
    else
        echo "⚠ No request duration metrics found"
    fi
}

# Test graceful degradation
test_graceful_degradation() {
    echo "Testing graceful degradation..."
    
    # Stop database service
    echo "Stopping database service..."
    docker-compose stop postgres
    
    # Wait a moment
    sleep 5
    
    # Check if application is still responsive
    if curl -s http://localhost:8000/health | jq -e '.status == "Degraded"' > /dev/null; then
        echo "✓ Application gracefully degraded when database is unavailable"
    else
        echo "⚠ Application did not gracefully degrade"
    fi
    
    # Restart database service
    echo "Restarting database service..."
    docker-compose start postgres
    
    # Wait for recovery
    sleep 10
    
    # Check if application recovered
    if curl -s http://localhost:8000/health | jq -e '.status == "Healthy"' > /dev/null; then
        echo "✓ Application recovered after database restart"
    else
        echo "⚠ Application did not recover after database restart"
    fi
}

# Run validation tests
check_application_health
test_circuit_breaker
test_retry_mechanism
test_rate_limiting
test_timeout_handling
test_graceful_degradation

echo "Resilience validation completed"