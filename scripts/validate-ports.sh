#!/bin/bash
# scripts/validate-ports.sh

set -e

ENVIRONMENT=${1:-development}
CONFIG_FILE="config/ports.yaml"
DOCKER_COMPOSE_FILE="docker-compose.yml"

echo "=== Port Configuration Validation ==="
echo "Environment: $ENVIRONMENT"
echo "Config File: $CONFIG_FILE"
echo "Docker Compose: $DOCKER_COMPOSE_FILE"
echo

# Check if required files exist
check_files() {
    echo "Checking required files..."
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "ERROR: Port configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    if [ ! -f "$DOCKER_COMPOSE_FILE" ]; then
        echo "ERROR: Docker Compose file not found: $DOCKER_COMPOSE_FILE"
        exit 1
    fi
    
    echo "✓ All required files found"
}

# Check for port conflicts
check_port_conflicts() {
    echo "Checking for port conflicts..."
    
    # Extract all port numbers from docker-compose.yml
    ports=$(grep -oP '^- \"\K[0-9]+(?=:)' "$DOCKER_COMPOSE_FILE" | sort -n)
    
    # Check for duplicates
    duplicate_ports=$(echo "$ports" | uniq -d)
    
    if [ -n "$duplicate_ports" ]; then
        echo "ERROR: Port conflicts detected:"
        echo "$duplicate_ports" | while read port; do
            echo "  - Port $port is used by multiple services"
        done
        exit 1
    else
        echo "✓ No port conflicts found"
    fi
}

# Check if ports are accessible
check_port_accessibility() {
    echo "Checking port accessibility..."
    
    # Define ports to check based on environment
    case $ENVIRONMENT in
        "development")
            check_ports=(8000 8001 9090 8080 5432 9187 6379 9121 9091 3000 16686 9100 8080)
            ;;
        "production")
            check_ports=(8000 8001 9090 8080 9091 3000 16686)
            ;;
        *)
            echo "ERROR: Unknown environment: $ENVIRONMENT"
            exit 1
            ;;
    esac
    
    for port in "${check_ports[@]}"; do
        if nc -z localhost "$port" 2>/dev/null; then
            echo "✓ Port $port is accessible"
        else
            echo "⚠ Port $port is not accessible (may be normal if service is not running)"
        fi
    done
}

# Check port security
check_port_security() {
    echo "Checking port security..."
    
    # Check if internal-only ports are exposed
    case $ENVIRONMENT in
        "production")
            # In production, internal ports should not be exposed
            internal_ports=(5432 9187 6379 9121 9100 8080)
            
            for port in "${internal_ports[@]}"; do
                if nc -z localhost "$port" 2>/dev/null; then
                    echo "⚠ WARNING: Internal port $port is accessible in production"
                fi
            done
            ;;
    esac
    
    # Check if authentication is required for sensitive ports
    sensitive_ports=(8000 8001 9090 9091 3000 16686)
    
    for port in "${sensitive_ports[@]}"; do
        if nc -z localhost "$port" 2>/dev/null; then
            echo "✓ Sensitive port $port is accessible - ensure authentication is configured"
        fi
    done
}

# Validate port configuration with application
validate_with_app() {
    echo "Validating port configuration with application..."
    
    # Check if application binary exists
    if [ ! -f "target/release/exploit_detector" ]; then
        echo "Application binary not found, skipping application validation"
        return
    fi
    
    # Start the application with validation mode
    if timeout 30 ./target/release/exploit_detector --validate-ports --environment "$ENVIRONMENT"; then
        echo "✓ Application port validation passed"
    else
        echo "⚠ Application port validation failed or timed out"
    fi
}

# Check Docker Compose configuration
check_docker_compose() {
    echo "Checking Docker Compose configuration..."
    
    # Validate Docker Compose file
    if docker-compose -f "$DOCKER_COMPOSE_FILE" config > /dev/null 2>&1; then
        echo "✓ Docker Compose configuration is valid"
    else
        echo "ERROR: Docker Compose configuration is invalid"
        exit 1
    fi
    
    # Check if all required services are defined
    required_services=("security-monitoring" "postgres" "redis" "nginx")
    for service in "${required_services[@]}"; do
        if grep -q "^  $service:" "$DOCKER_COMPOSE_FILE"; then
            echo "✓ Service $service is defined"
        else
            echo "ERROR: Required service $service is missing"
            exit 1
        fi
    done
}

# Generate port validation report
generate_report() {
    echo "Generating port validation report..."
    
    report_file="port-validation-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "Port Validation Report"
        echo "====================="
        echo "Generated: $(date)"
        echo "Environment: $ENVIRONMENT"
        echo
        
        echo "Port Assignments:"
        grep -oP '^- \"\K[0-9]+(?=:)' "$DOCKER_COMPOSE_FILE" | sort -n | while read port; do
            service=$(grep -B5 "$port:" "$DOCKER_COMPOSE_FILE" | grep "^[a-zA-Z]" | tail -1 | sed 's/://')
            echo "  $port: $service"
        done
        echo
        
        echo "Security Status:"
        case $ENVIRONMENT in
            "production")
                echo "  - Internal ports should not be exposed externally"
                echo "  - All external ports require authentication"
                echo "  - HTTPS enforced for all external services"
                ;;
            "development")
                echo "  - All ports accessible for development"
                echo "