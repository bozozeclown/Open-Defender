# Port Management Documentation

## Port Assignments

### Application Ports
| Service | Port | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|---------|----------------|---------------|------------|
| GraphQL API | 8000 | GraphQL API endpoint | Yes | Yes | Yes |
| WebSocket | 8001 | WebSocket for real-time updates | Yes | Yes | Yes |
| Metrics | 9090 | Prometheus metrics endpoint | Limited | Yes | No |
| Health | 8080 | Health check endpoint | Limited | No | No |

### Database Ports
| Service | Port | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|---------|----------------|---------------|------------|
| PostgreSQL | 5432 | Database connection | No | Yes | No |
| PostgreSQL Exporter | 9187 | Database metrics | No | No | No |

### Cache Ports
| Service | Port | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|---------|----------------|---------------|------------|
| Redis | 6379 | Cache connection | No | Yes | No |
| Redis Exporter | 9121 | Cache metrics | No | No | No |

### Monitoring Ports
| Service | Port | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|---------|----------------|---------------|------------|
| Prometheus UI | 9091 | Prometheus web interface | Yes | Yes | Yes |
| Prometheus Metrics | 9090 | Internal metrics scraping | No | Yes | No |
| Grafana | 3000 | Grafana dashboard interface | Yes | Yes | Yes |
| Jaeger UI | 16686 | Jaeger tracing interface | Yes | Yes | Yes |
| Node Exporter | 9100 | System metrics | No | No | No |
| cAdvisor | 8080 | Container metrics | No | No | No |

### Development Ports
| Service | Port | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|---------|----------------|---------------|------------|
| Debug | 5858 | Debugging interface | Development only | No | No |
| Hot Reload | 35729 | Live reload for development | Development only | No | No |

## Environment-Specific Port Mappings

### Development Environment
All services are exposed on their default ports for easy access during development.

### Production Environment
- Application services (GraphQL, WebSocket) are exposed through HTTPS (port 443) via ingress
- Internal services (database, cache) are not exposed externally
- Monitoring services are exposed with authentication
- Metrics endpoints require authentication

## Port Security Guidelines

1. **Internal Only Ports**: Database, cache, and system metrics ports should never be exposed externally
2. **Authentication Required**: All external-facing APIs and metrics should require authentication
3. **HTTPS Only**: All user-facing services should use HTTPS
4. **Firewall Rules**: Implement firewall rules to restrict access to specific ports
5. **Network Segmentation**: Use separate networks for different service tiers

## Port Validation

The system includes automatic port conflict detection:
- Validates that no two services use the same port
- Ensures internal-only ports are not exposed in production
- Verifies that authentication requirements are met

## Troubleshooting

### Common Port Issues

1. **Port Already in Use**
   - Check if another process is using the port: `netstat -tulpn | grep :<port>`
   - Stop the conflicting process or change the port assignment

2. **Connection Refused**
   - Verify the service is running: `docker ps`
   - Check the service logs: `docker logs <service_name>`
   - Ensure the port is properly mapped in docker-compose.yml

3. **Permission Denied**
   - Check if the port requires special privileges (ports < 1024)
   - Verify user permissions for the port

### Port Testing Commands

```bash
# Test if a port is accessible
telnet localhost <port>
nc -z localhost <port>
curl http://localhost:<port>

# Check which process is using a port
sudo lsof -i :<port>
sudo netstat -tulpn | grep :<port>

# Test port connectivity between containers
docker exec <container1> nc -z <container2> <port>


### 5. Create Port Validation Script

```bash
#!/bin/bash
# scripts/validate-ports.sh

set -e

ENVIRONMENT=${1:-development}

echo "Validating port configuration for environment: $ENVIRONMENT"

# Load port configuration
if [ ! -f "config/ports.yaml" ]; then
    echo "ERROR: Port configuration file not found"
    exit 1
fi

# Check for port conflicts
check_port_conflicts() {
    echo "Checking for port conflicts..."
    
    # Extract all port numbers from docker-compose.yml
    ports=$(grep -oP '^- "\K[0-9]+(?=:)' docker-compose.yml | sort -n)
    
    # Check for duplicates
    duplicate_ports=$(echo "$ports" | uniq -d)
    
    if [ -n "$duplicate_ports" ]; then
        echo "ERROR: Port conflicts detected:"
        echo "$duplicate_ports"
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
            echo "Unknown environment: $ENVIRONMENT"
            exit 1
            ;;
    esac
    
    for port in "${check_ports[@]}"; do
        if nc -z localhost $port; then
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
                if nc -z localhost $port; then
                    echo "⚠ Internal port $port is accessible in production"
                fi
            done
            ;;
    esac
    
    # Check if authentication is required for sensitive ports
    sensitive_ports=(8000 8001 9090 9091 3000 16686)
    
    for port in "${sensitive_ports[@]}"; do
        if nc -z localhost $port; then
            echo "✓ Sensitive port $port is accessible - ensure authentication is configured"
        fi
    done
}

# Validate port configuration with application
validate_with_app() {
    echo "Validating port configuration with application..."
    
    # Start the application with validation mode
    if [ -f "target/release/exploit_detector" ]; then
        ./target/release/exploit_detector --validate-ports --environment $ENVIRONMENT
    else
        echo "Application binary not found, skipping application validation"
    fi
}

# Run validation checks
check_port_conflicts
check_port_accessibility
check_port_security
validate_with_app

echo "Port validation completed successfully"