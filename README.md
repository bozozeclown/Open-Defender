# Security Monitoring System

A comprehensive, real-time security monitoring and incident response platform built with Rust, designed to detect, analyze, and respond to security threats across your infrastructure.

## Architecture Overview

The system is built with a microservices architecture with the following components:

### Core Services
- **Security Monitoring Application** (Rust): Main application handling GraphQL API, WebSocket, and event processing
- **PostgreSQL**: Primary database for storing security events and configuration
- **Redis**: Cache for session management and real-time collaboration
- **HashiCorp Vault**: Secrets management for secure credential storage

### Monitoring & Observability
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Dashboards and visualization
- **Jaeger**: Distributed tracing
- **Node Exporter**: System metrics
- **cAdvisor**: Container metrics

### Security & Networking
- **Nginx**: Reverse proxy with SSL termination and security headers
- **Network Segmentation**: Separate networks for backend services and monitoring

## Features

### 🛡️ Security Monitoring
- **Real-time Event Collection**: Monitor network traffic, process activity, file operations, and system logs
- **Advanced Threat Detection**: Port scanning, data exfiltration, suspicious processes, and file activity detection
- **Pattern Recognition**: Identify attack patterns and correlate events to detect sophisticated threats
- **Anomaly Detection**: Statistical analysis to identify unusual behavior and potential security incidents

### 🔒 Security Hardening
- **Authentication**: JWT-based authentication with MFA support
- **Authorization**: Role-based access control (RBAC) with fine-grained permissions
- **Secrets Management**: Integration with HashiCorp Vault
- **Audit Logging**: Comprehensive audit trails for all security events
- **Network Security**: TLS encryption, security headers, and network segmentation

### 🚨 Resilience & Reliability
- **Circuit Breakers**: Prevent cascading failures when services are unavailable
- **Retry Mechanisms**: Automatic retry for transient failures with exponential backoff
- **Health Checks**: Comprehensive health monitoring with dependency checks
- **Graceful Degradation**: Application continues to function when dependencies fail
- **Rate Limiting**: Protect against abuse and DoS attacks

### 📊 Analytics & Reporting
- **Real-time Metrics**: System performance, event rates, and detection statistics
- **Alert Management**: Intelligent alerting with deduplication and correlation
- **Customizable Dashboards**: Monitor system health and security posture
- **Historical Analysis**: Trend analysis and incident reporting

### 👥 Collaboration
- **Real-time Chat**: Team communication during security incidents
- **Workspace Management**: Organize incidents and share artifacts with team members
- **Live Collaboration**: Real-time cursor positions and typing indicators
- **Artifact Sharing**: Share evidence and analysis results across the team

### 🔧 Observability
- **Distributed Tracing**: End-to-end request tracing with Jaeger
- **Metrics Collection**: Prometheus-based metrics monitoring
- **Structured Logging**: Comprehensive logging with multiple levels
- **Health Checks**: System health monitoring and status reporting

## Quick Start

### Prerequisites

- Rust 1.75+ (install from [rustup.rs](https://rustup.rs/))
- Docker 20.10+ and Docker Compose 2.0+
- PostgreSQL 13+
- Redis 6+
- HashiCorp Vault (for production)

### Development Setup

1. **Clone the repository**
```bash
git clone https://github.com/your-org/security-monitoring.git
cd security-monitoring
```

2. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Install dependencies**
```bash
cargo build --release
```

4. **Set up the database**
```bash
# Create database
createdb security_monitoring

# Run migrations
cargo run --bin migrate
```

5. **Start the services**
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### Production Deployment

1. **Prepare the environment**
```bash
# Set production environment variables
export ENVIRONMENT=production
export DATABASE_URL=postgres://user:password@prod-db:5432/security_monitoring
export REDIS_URL=redis://prod-redis:6379
export VAULT_URL=https://vault.yourdomain.com
export VAULT_TOKEN=your-vault-token
export JWT_SECRET=your-super-secret-jwt-key-change-in-production
```

2. **Deploy using Docker Compose**
```bash
# Deploy with production configuration
./scripts/deploy.sh production
```

3. **Or deploy using Kubernetes**
```bash
# Apply Kubernetes configurations
kubectl apply -f k8s/

# Verify deployment
kubectl get pods -n security-monitoring
```

## Configuration

### Environment Variables

The system uses environment variables for configuration. Key configuration options:

#### Database
```bash
DATABASE_URL=postgres://user:password@localhost/security_monitoring
DB_MAX_CONNECTIONS=20
DB_MIN_CONNECTIONS=5
DB_POOL_TIMEOUT=30
```

#### Analytics
```bash
EVENT_BUFFER_SIZE=50000
PORT_SCAN_THRESHOLD=100
DATA_EXFILTRATION_THRESHOLD=52428800
SUSPICIOUS_PROCESSES=powershell.exe,cmd.exe,wscript.exe,cscript.exe,rundll32.exe,regsvr32.exe
SYSTEM_METRICS_INTERVAL=30
```

#### API
```bash
GRAPHQL_ENDPOINT=0.0.0.0:8443
JWT_SECRET=your-secret-key-here
CORS_ORIGINS=https://security.yourdomain.com
```

#### Security
```bash
VAULT_URL=https://vault.yourdomain.com
VAULT_TOKEN=your-vault-token
MFA_ENABLED=true
RBAC_ENABLED=true
```

#### Observability
```bash
RUST_LOG=info
JAEGER_ENDPOINT=jaeger:6831
METRICS_ENDPOINT=0.0.0.0:9090
```

### Configuration Files

The system uses YAML configuration files for more complex settings:

- `config/config.yaml`: Main application configuration
- `config/services.yaml`: Service discovery configuration
- `config/ports.yaml`: Port management configuration
- `config/security.yaml`: Security configuration

## API Documentation

### GraphQL API

Access the GraphQL Playground at `https://security.yourdomain.com/graphql` for interactive API exploration.

#### Authentication

All API requests require authentication using JWT tokens:

```bash
# Login to get token
curl -X POST https://security.yourdomain.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"admin\", password: \"password\") { token } }"}'

# Use token in subsequent requests
curl -X POST https://security.yourdomain.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{"query": "query { events(limit: 10) { event_id timestamp } }"}'
```

#### Example Queries

**Get recent events:**
```graphql
query GetEvents {
  events(limit: 10, offset: 0) {
    event_id
    event_type
    timestamp
    data
  }
}
```

**Get system health:**
```graphql
query GetHealth {
  systemHealth {
    status
    checks {
      name
      status
      value
      message
    }
  }
}
```

**Create an incident:**
```graphql
mutation CreateIncident {
  createIncident(
    title: "Suspicious Network Activity",
    description: "Multiple connection attempts detected",
    severity: "high"
  ) {
    id
    title
    status
    created_at
  }
}
```

### WebSocket API

Connect to the WebSocket server at `wss://security.yourdomain.com/ws` for real-time collaboration.

#### Message Format

```json
{
  "type": "chat",
  "workspace_id": "workspace-123",
  "message": "Investigating the suspicious activity",
  "message_type": "text"
}
```

### REST Endpoints

- `GET /health`: System health status
- `GET /metrics`: Prometheus metrics endpoint (requires authentication)
- `GET /ready`: Readiness probe
- `GET /live`: Liveness probe

## Development

### Project Structure

```
src/
├── analytics/          # Security analytics and detection engine
├── api/               # GraphQL API server
├── auth/              # Authentication and authorization
├── collaboration/     # Real-time collaboration features
├── collectors/        # Event collection from various sources
├── config/            # Configuration management
├── database/          # Database connection and management
├── error/             # Error handling and types
├── health/            # Health check system
├── network/           # Network configuration and port management
├── observability/     # Metrics, tracing, and logging
├── resilience/        # Circuit breakers, retry mechanisms
├── security/          # Security features and audit logging
├── service_discovery/ # Service discovery and health monitoring
└── main.rs           # Application entry point

tests/
├── integration/       # Integration tests
└── unit/             # Unit tests

config/               # Configuration files
├── config.yaml
├── services.yaml
├── ports.yaml
└── security.yaml

docs/                 # Additional documentation
├── api/              # API documentation
├── deployment/       # Deployment guides
└── troubleshooting/  # Troubleshooting guides

scripts/              # Utility scripts
├── deploy.sh
├── validate-*.sh
└── backup.sh

k8s/                  # Kubernetes configurations
monitoring/           # Monitoring configurations
└── nginx/            # Nginx configuration
```

### Building and Testing

```bash
# Build the project
cargo build --release

# Run tests
cargo test

# Run integration tests
cargo test --test integration_tests

# Run with specific features
cargo run --features "jaeger,prometheus"

# Check code formatting
cargo fmt

# Run clippy lints
cargo clippy
```

### Adding New Collectors

To add a new event collector:

1. Create a new module in `src/collectors/`
2. Implement the `EventCollector` trait
3. Add the collector to the main event collection loop
4. Add corresponding event types to `EventData` enum

Example:
```rust
// src/collectors/dns_collector.rs
pub struct DnsCollector {
    // Collector-specific fields
}

impl EventCollector for DnsCollector {
    async fn collect(&self) -> Result<Vec<DataEvent>> {
        // Collection logic
    }
}
```

### Adding New Detection Rules

To add new detection rules:

1. Add the rule to `AnalyticsManager`
2. Implement the detection logic
3. Configure thresholds in the configuration
4. Add corresponding alert types

Example:
```rust
impl AnalyticsManager {
    async fn detect_dns_tunneling(&self, event: &DataEvent) -> Result<()> {
        // Detection logic
    }
}
```

## Deployment

### Production Deployment

1. **Environment Setup**
```bash
# Set production environment variables
export RUST_LOG=info
export DATABASE_URL=postgres://user:pass@prod-db:5432/security_monitoring
export REDIS_URL=redis://prod-redis:6379
export VAULT_URL=https://vault.yourdomain.com
export VAULT_TOKEN=your-vault-token
export JWT_SECRET=your-super-secret-jwt-key
```

2. **Database Migration**
```bash
# Run production migrations
cargo run --bin migrate -- --env production
```

3. **Service Deployment**
```bash
# Deploy with systemd
sudo systemctl start security-monitoring

# Or use Docker
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-monitoring
  namespace: security-monitoring
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-monitoring
  template:
    metadata:
      labels:
        app: security-monitoring
    spec:
      serviceAccountName: security-monitoring-sa
      containers:
      - name: security-monitoring
        image: your-registry/security-monitoring:latest
        ports:
        - containerPort: 8443
        env:
        - name: RUST_LOG
          value: "info"
        - name: ENVIRONMENT
          value: "production"
        envFrom:
        - configMapRef:
            name: security-monitoring-config
        - secretRef:
            name: security-monitoring-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8443
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
```

### Monitoring Setup

1. **Prometheus Configuration**
```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'security-monitoring'
    static_configs:
      - targets: ['security-monitoring:9090']
    metrics_path: '/metrics'
    scrape_interval: 10s
    basic_auth:
      username: '${METRICS_USERNAME}'
      password: '${METRICS_PASSWORD}'
```

2. **Grafana Dashboards**
Import the provided dashboards from `monitoring/grafana/dashboards/` or create custom dashboards using the available metrics.

## Troubleshooting

### Common Issues

#### Service Won't Start
**Symptoms**: Container exits immediately or service fails to start

**Solutions**:
1. Check logs: `docker-compose logs security-monitoring`
2. Verify configuration: `./scripts/validate-config.sh`
3. Check dependencies: `./scripts/validate-dependencies.sh`
4. Verify environment variables: `env | grep -E '(DATABASE_URL|REDIS_URL|JWT_SECRET)'`

#### Database Connection Issues
**Symptoms**: "Connection refused" or "authentication failed" errors

**Solutions**:
1. Check database status: `docker-compose ps postgres`
2. Verify connection string: `./scripts/validate-db-connections.sh`
3. Check database logs: `docker-compose logs postgres`
4. Test connectivity: `docker-compose exec security-monitoring psql $DATABASE_URL -c "SELECT 1"`

#### High Memory Usage
**Symptoms**: Service consuming excessive memory

**Solutions**:
1. Check memory metrics: `curl -s http://localhost:9090/metrics | grep memory`
2. Review configuration: Check buffer sizes and connection pools
3. Monitor for memory leaks: Use `valgrind` or `heaptrack`
4. Adjust resource limits: Update Docker memory limits or Kubernetes requests/limits

#### Authentication Issues
**Symptoms**: 401 Unauthorized or 403 Forbidden errors

**Solutions**:
1. Verify JWT secret: Check `JWT_SECRET` environment variable
2. Check token expiration: Decode JWT at https://jwt.io
3. Verify user permissions: Check RBAC configuration
4. Review audit logs: `tail -f logs/security_audit.log`

#### Performance Issues
**Symptoms**: Slow response times or high latency

**Solutions**:
1. Check metrics: Access Grafana dashboard
2. Monitor database queries: Enable query logging
3. Check for blocking operations: Use profiling tools
4. Review circuit breaker status: Check `/health` endpoint

### Diagnostic Commands

```bash
# Check overall system health
curl -s https://security.yourdomain.com/health | jq .

# Check database connectivity
./scripts/validate-db-connections.sh

# Check network connectivity
./scripts/validate-network.sh

# Check port assignments
./scripts/validate-ports.sh

# Check security configuration
./scripts/validate-security.sh

# Check resilience patterns
./scripts/validate-resilience.sh

# View recent errors
docker-compose logs security-monitoring | grep ERROR | tail -20

# Monitor resource usage
docker stats security-monitoring

# Check Kubernetes pod status
kubectl get pods -n security-monitoring
kubectl describe pod <pod-name> -n security-monitoring
```

### Log Analysis

```bash
# View application logs
docker-compose logs -f security-monitoring

# Filter for errors
docker-compose logs security-monitoring | grep ERROR

# View database logs
docker-compose logs postgres

# View Redis logs
docker-compose logs redis

# View Nginx logs
docker-compose logs nginx

# View audit logs
tail -f logs/security_audit.log | jq .

# View metrics
curl -s https://security.yourdomain.com/metrics | grep -E "(http_requests_total|db_connections_active)"
```

## Support

- **Documentation**: Full documentation is available at [docs.example.com](https://docs.example.com)
- **Issues**: Report bugs and request features on [GitHub Issues](https://github.com/your-org/security-monitoring/issues)
- **Discussions**: Join our community discussions on [GitHub Discussions](https://github.com/your-org/security-monitoring/discussions)
- **Email**: Contact the team at security@example.com

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`cargo test`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Use clippy lints (`cargo clippy`)
- Write documentation for public APIs
- Include unit tests for new functionality
- Follow the existing code structure and patterns

### Reporting Issues

Please use the GitHub Issues page to report bugs or request features. Include:

- A clear description of the issue
- Steps to reproduce the problem
- Expected behavior
- Actual behavior
- Environment information (OS, Rust version, etc.)
- Relevant logs or error messages

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Rust](https://www.rust-lang.org/) for providing a safe and performant language
- [GraphQL](https://graphql.org/) for the powerful API specification
- [PostgreSQL](https://www.postgresql.org/) for the reliable database
- [Redis](https://redis.io/) for the fast in-memory data store
- [Prometheus](https://prometheus.io/) for metrics and monitoring
- [Grafana](https://grafana.com/) for beautiful dashboards
- [Jaeger](https://www.jaegertracing.io/) for distributed tracing
- [HashiCorp Vault](https://www.vaultproject.io/) for secrets management
- [Nginx](https://nginx.org/) for the reverse proxy
- The open-source community for various libraries and tools

---

**Security Note**: This is a security monitoring tool. Please ensure proper security measures are in place when deploying in production environments, including proper authentication, authorization, network security controls, and regular security audits.
```

### 2. Create Deployment Verification Script

```bash
#!/bin/bash
# scripts/verify-deployment.sh

set -e

ENVIRONMENT=${1:-production}
NAMESPACE=${2:-security-monitoring}

echo "Verifying deployment for environment: $ENVIRONMENT"
echo "Namespace: $NAMESPACE"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required tools are installed
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    log_info "All prerequisites are installed"
}

# Verify Kubernetes cluster connectivity
verify_cluster_connectivity() {
    log_info "Verifying Kubernetes cluster connectivity..."
    
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Kubernetes cluster is accessible"
}

# Verify namespace exists
verify_namespace() {
    log_info "Verifying namespace: $NAMESPACE"
    
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace $NAMESPACE does not exist"
        exit 1
    fi
    
    log_info "Namespace $NAMESPACE exists"
}

# Verify all pods are running
verify_pods() {
    log_info "Verifying pod status..."
    
    local pods=($(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
    
    if [ ${#pods[@]} -eq 0 ]; then
        log_error "No pods found in namespace $NAMESPACE"
        exit 1
    fi
    
    local unhealthy_pods=()
    
    for pod in "${pods[@]}"; do
        local status=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}')
        
        if [ "$status" != "Running" ]; then
            unhealthy_pods+=("$pod ($status)")
        fi
    done
    
    if [ ${#unhealthy_pods[@]} -ne 0 ]; then
        log_error "Unhealthy pods found: ${unhealthy_pods[*]}"
        exit 1
    fi
    
    log_info "All pods are running"
}

# Verify services are accessible
verify_services() {
    log_info "Verifying services..."
    
    local services=($(kubectl get svc -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
    
    if [ ${#services[@]} -eq 0 ]; then
        log_error "No services found in namespace $NAMESPACE"
        exit 1
    fi
    
    for service in "${services[@]}"; do
        local service_type=$(kubectl get svc "$service" -n "$NAMESPACE" -o jsonpath='{.spec.type}')
        
        if [ "$service_type" = "LoadBalancer" ]; then
            local ingress=$(kubectl get svc "$service" -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
            if [ -z "$ingress" ]; then
                log_warn "Service $service has no external IP assigned"
            else
                log_info "Service $service is accessible at $ingress"
            fi
        elif [ "$service_type" = "NodePort" ]; then
            local node_port=$(kubectl get svc "$service" -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}')
            log_info "Service $service is accessible on node port $node_port"
        else
            log_info "Service $service is of type $service_type"
        fi
    done
}

# Verify ingress configuration
verify_ingress() {
    log_info "Verifying ingress configuration..."
    
    if ! kubectl get ingress -n "$NAMESPACE" &> /dev/null; then
        log_warn "No ingress resources found in namespace $NAMESPACE"
        return
    fi
    
    local ingresses=($(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
    
    for ingress in "${ingresses[@]}"; do
        local hosts=($(kubectl get ingress "$ingress" -n "$NAMESPACE" -o jsonpath='{.spec.rules[*].host}'))
        
        for host in "${hosts[@]}"; do
            if curl -s -o /dev/null -w "%{http_code}" "https://$host/health" | grep -q "200"; then
                log_info "Ingress $ingress for host $host is accessible"
            else
                log_warn "Ingress $ingress for host $host is not accessible"
            fi
        done
    done
}

# Verify health endpoints
verify_health_endpoints() {
    log_info "Verifying health endpoints..."
    
    # Get application service
    local app_service=$(kubectl get svc -n "$NAMESPACE" -l app=security-monitoring -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$app_service" ]; then
        log_error "Application service not found"
        exit 1
    fi
    
    # Port forward to access the service
    local local_port=8080
    kubectl port-forward -n "$NAMESPACE" "svc/$app_service" "$local_port:8443" &
    local port_forward_pid=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Test health endpoint
    if curl -s "http://localhost:$local_port/health" | jq -e '.status == "Healthy"' > /dev/null; then
        log_info "Health endpoint is responding correctly"
    else
        log_error "Health endpoint is not responding correctly"
        kill $port_forward_pid
        exit 1
    fi
    
    # Test ready endpoint
    if curl -s "http://localhost:$local_port/ready" | jq -e '.ready == true' > /dev/null; then
        log_info "Ready endpoint is responding correctly"
    else
        log_error "Ready endpoint is not responding correctly"
        kill $port_forward_pid
        exit 1
    fi
    
    # Test live endpoint
    if curl -s "http://localhost:$local_port/live" | jq -e '.alive == true' > /dev/null; then
        log_info "Live endpoint is responding correctly"
    else
        log_error "Live endpoint is not responding correctly"
        kill $port_forward_pid
        exit 1
    fi
    
    # Clean up port forward
    kill $port_forward_pid
}

# Verify metrics endpoint
verify_metrics_endpoint() {
    log_info "Verifying metrics endpoint..."
    
    # Get application service
    local app_service=$(kubectl get svc -n "$NAMESPACE" -l app=security-monitoring -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$app_service" ]; then
        log_error "Application service not found"
        exit 1
    fi
    
    # Port forward to access the service
    local local_port=9090
    kubectl port-forward -n "$NAMESPACE" "svc/$app_service" "$local_port:9090" &
    local port_forward_pid=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    # Test metrics endpoint with authentication
    local metrics_username=${METRICS_USERNAME:-admin}
    local metrics_password=${METRICS_PASSWORD:-admin}
    
    if curl -s -u "$metrics_username:$metrics_password" "http://localhost:$local_port/metrics" | grep -q "http_requests_total"; then
        log_info "Metrics endpoint is responding correctly"
    else
        log_error "Metrics endpoint is not responding correctly"
        kill $port_forward_pid
        exit 1
    fi
    
    # Clean up port forward
    kill $port_forward_pid
}

# Verify database connectivity
verify_database_connectivity() {
    log_info "Verifying database connectivity..."
    
    # Get database pod
    local db_pod=$(kubectl get pods -n "$NAMESPACE" -l app=postgres -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$db_pod" ]; then
        log_error "Database pod not found"
        exit 1
    fi
    
    # Test database connectivity from application pod
    local app_pod=$(kubectl get pods -n "$NAMESPACE" -l app=security-monitoring -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$app_pod" ]; then
        log_error "Application pod not found"
        exit 1
    fi
    
    if kubectl exec -n "$NAMESPACE" "$app_pod" -- pg_isready -h postgres -U postgres; then
        log_info "Database connectivity is working"
    else
        log_error "Database connectivity is not working"
        exit 1
    fi
}

# Verify Redis connectivity
verify_redis_connectivity() {
    log_info "Verifying Redis connectivity..."
    
    # Get Redis pod
    local redis_pod=$(kubectl get pods -n "$NAMESPACE" -l app=redis -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$redis_pod" ]; then
        log_error "Redis pod not found"
        exit 1
    fi
    
    # Test Redis connectivity from application pod
    local app_pod=$(kubectl get pods -n "$NAMESPACE" -l app=security-monitoring -o jsonpath='{.items[0].metadata.name}')
    
    if [ -z "$app_pod" ]; then
        log_error "Application pod not found"
        exit 1
    fi
    
    if kubectl exec -n "$NAMESPACE" "$app_pod" -- redis-cli -h redis ping | grep -q "PONG"; then
        log_info "Redis connectivity is working"
    else
        log_error "Redis connectivity is not working"
        exit 1
    fi
}

# Verify resource usage
verify_resource_usage() {
    log_info "Verifying resource usage..."
    
    local pods=($(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
    
    for pod in "${pods[@]}"; do
        local cpu_request=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.requests.cpu}')
        local memory_request=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.requests.memory}')
        local cpu_limit=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.limits.cpu}')
        local memory_limit=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.spec.containers[0].resources.limits.memory}')
        
        log_info "Pod $pod: CPU=${cpu_request:-unspecified}/${cpu_limit:-unlimited}, Memory=${memory_request:-unspecified}/${memory_limit:-unlimited}"
        
        # Check actual usage
        local cpu_usage=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $2}')
        local memory_usage=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $3}')
        
        if [ -n "$cpu_usage" ]; then
            log_info "Pod $pod usage: CPU=$cpu_usage, Memory=$memory_usage"
        fi
    done
}

# Verify security configurations
verify_security_configurations() {
    log_info "Verifying security configurations..."
    
    # Check for secrets
    local secrets=($(kubectl get secrets -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
    
    if [[ ! " ${secrets[*]} " =~ " security-monitoring-secrets " ]]; then
        log_error "Security monitoring secrets not found"
        exit 1
    fi
    
    # Check for RBAC
    local roles=($(kubectl get roles -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
    
    if [ ${#roles[@]} -eq 0 ]; then
        log_error "No RBAC roles found"
        exit 1
    fi
    
    # Check for Pod Security Policies
    if kubectl get psp -n "$NAMESPACE" &> /dev/null; then
        local psps=($(kubectl get psp -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
        
        if [ ${#psps[@]} -eq 0 ]; then
            log_warn "No Pod Security Policies found"
        else
            log_info "Pod Security Policies found: ${psps[*]}"
        fi
    fi
    
    # Check for Network Policies
    local netpols=($(kubectl get networkpolicy -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'))
    
    if [ ${#netpols[@]} -eq 0 ]; then
        log_warn "No Network Policies found"
    else
        log_info "Network Policies found: ${netpols[*]}"
    fi
}

# Generate deployment report
generate_deployment_report() {
    log_info "Generating deployment report..."
    
    local report_file="deployment-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "Security Monitoring System Deployment Report"
        echo "=========================================="
        echo "Environment: $ENVIRONMENT"
        echo "Namespace: $NAMESPACE"
        echo "Generated: $(date)"
        echo ""
        
        echo "Cluster Information:"
        echo "-------------------"
        kubectl cluster-info
        echo ""
        
        echo "Namespace Status:"
        echo "-----------------"
        kubectl get namespace "$NAMESPACE"
        echo ""
        
        echo "Pod Status:"
        echo "-----------"
        kubectl get pods -n "$NAMESPACE" -o wide
        echo ""
        
        echo "Service Status:"
        echo "---------------"
        kubectl get svc -n "$NAMESPACE"
        echo ""
        
        echo "Ingress Status:"
        echo "---------------"
        kubectl get ingress -n "$NAMESPACE"
        echo ""
        
        echo "Resource Usage:"
        echo "--------------"
        kubectl top pods -n "$NAMESPACE"
        echo ""
        
        echo "Events:"
        echo "-------"
        kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp'
        echo ""
        
    } > "$report_file"
    
    log_info "Deployment report generated: $report_file"
}

# Main verification process
main() {
    log_info "Starting deployment verification..."
    
    check_prerequisites
    verify_cluster_connectivity
    verify_namespace
    verify_pods
    verify_services
    verify_ingress
    verify_health_endpoints
    verify_metrics_endpoint
    verify_database_connectivity
    verify_redis_connectivity
    verify_resource_usage
    verify_security_configurations
    generate_deployment_report
    
    log_info "Deployment verification completed successfully!"
}

# Run main function
main "$@"
```

### 3. Create Comprehensive Troubleshooting Guide

```markdown
# docs/troubleshooting/TROUBLESHOOTING.md

# Troubleshooting Guide

This guide provides systematic procedures for diagnosing and resolving common issues with the Security Monitoring System.

## Table of Contents

1. [Quick Diagnosis](#quick-diagnosis)
2. [Common Issues](#common-issues)
   - [Service Startup Issues](#service-startup-issues)
   - [Database Connection Issues](#database-connection-issues)
   - [Authentication Issues](#authentication-issues)
   - [Performance Issues](#performance-issues)
   - [Memory Issues](#memory-issues)
   - [Network Issues](#network-issues)
   - [Kubernetes Issues](#kubernetes-issues)
3. [Diagnostic Tools](#diagnostic-tools)
4. [Log Analysis](#log-analysis)
5. [Performance Profiling](#performance-profiling)
6. [Emergency Procedures](#emergency-procedures)

## Quick Diagnosis

When experiencing issues, follow these quick steps to identify the problem:

### 1. Check System Health
```bash
# Check overall system health
curl -s https://security.yourdomain.com/health | jq .

# Check if all services are running
kubectl get pods -n security-monitoring

# Check resource usage
kubectl top pods -n security-monitoring
```

### 2. Check Recent Errors
```bash
# View recent application errors
docker-compose logs security-monitoring | grep ERROR | tail -20

# Check Kubernetes events
kubectl get events -n security-monitoring --sort-by='.lastTimestamp'

# View system logs
journalctl -u security-monitoring -n 100
```

### 3. Verify Connectivity
```bash
# Test database connectivity
./scripts/validate-db-connections.sh

# Test network connectivity
./scripts/validate-network.sh

# Test service health
./scripts/validate-health.sh
```

## Common Issues

### Service Startup Issues

#### Symptoms
- Container exits immediately
- Service fails to start
- Pod stuck in CrashLoopBackOff

#### Diagnosis
```bash
# Check container logs
docker-compose logs security-monitoring

# Check Kubernetes pod status
kubectl describe pod <pod-name> -n security-monitoring

# Check recent events
kubectl get events -n security-monitoring
```

#### Solutions

**1. Configuration Issues**
```bash
# Validate configuration
./scripts/validate-config.sh

# Check environment variables
env | grep -E '(DATABASE_URL|REDIS_URL|JWT_SECRET|RUST_LOG)'

# Verify configuration files
kubectl get configmap security-monitoring-config -n security-monitoring -o yaml
```

**2. Missing Dependencies**
```bash
# Check if all dependencies are running
docker-compose ps

# Verify database is ready
kubectl exec -it <postgres-pod> -n security-monitoring -- pg_isready

# Verify Redis is ready
kubectl exec -it <redis-pod> -n security-monitoring -- redis-cli ping
```

**3. Resource Constraints**
```bash
# Check resource usage
kubectl top pods -n security-monitoring

# Check pod events for OOM (Out of Memory)
kubectl describe pod <pod-name> -n security-monitoring | grep -i oom

# Increase memory limits if needed
kubectl edit deployment security-monitoring -n security-monitoring
```

### Database Connection Issues

#### Symptoms
- "Connection refused" errors
- Authentication failures
- Slow database queries
- Connection pool exhaustion

#### Diagnosis
```bash
# Test database connectivity
./scripts/validate-db-connections.sh

# Check database logs
docker-compose logs postgres

# Check connection pool metrics
curl -s http://localhost:9090/metrics | grep db_connections

# Monitor active connections
kubectl exec -it <postgres-pod> -n security-monitoring -- psql -c "SELECT count(*) FROM pg_stat_activity;"
```

#### Solutions

**1. Connection String Issues**
```bash
# Verify connection string format
echo $DATABASE_URL

# Test connection manually
kubectl exec -it <app-pod> -n security-monitoring -- psql $DATABASE_URL -c "SELECT 1;"

# Update connection string if needed
kubectl edit configmap security-monitoring-config -n security-monitoring
```

**2. Connection Pool Configuration**
```yaml
# config/config.yaml
database:
  max_connections: 20
  min_connections: 5
  pool_timeout: 30
  idle_timeout: 300
```

**3. Database Performance Issues**
```sql
-- Check for long-running queries
SELECT query, calls, total_time, mean_time, max_time 
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 10;

-- Check table sizes
SELECT 
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check for missing indexes
SELECT 
  schemaname,
  tablename,
  indexname,
  indexdef
FROM pg_indexes 
WHERE schemaname = 'public';
```

### Authentication Issues

#### Symptoms
- 401 Unauthorized errors
- 403 Forbidden errors
- JWT validation failures
- Permission denied errors

#### Diagnosis
```bash
# Check authentication logs
tail -f logs/security_audit.log | jq 'select(.action | contains("auth"))'

# Test JWT token
curl -X POST https://security.yourdomain.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { login(username: \"admin\", password: \"password\") { token } }"}'

# Verify JWT secret
echo $JWT_SECRET | wc -c
```

#### Solutions

**1. JWT Configuration**
```bash
# Verify JWT secret length (minimum 32 characters)
if [ ${#JWT_SECRET} -lt 32 ]; then
    echo "JWT secret is too short"
    exit 1
fi

# Check JWT expiration
echo $JWT_TOKEN | jq -R 'split(".") | .[1] | @base64d | fromjson | .exp'
```

**2. RBAC Configuration**
```yaml
# config/security.yaml
authorization:
  rbac_enabled: true
  default_role: "viewer"
  roles:
    admin:
      permissions: ["*"]
    analyst:
      permissions: ["events:read", "incidents:read", "incidents:write"]
    viewer:
      permissions: ["events:read"]
```

**3. User Permissions**
```sql
-- Check user roles
SELECT username, roles FROM users WHERE username = 'your_username';

-- Check role permissions
SELECT role_name, permission_name FROM role_permissions 
WHERE role_name IN (SELECT unnest(roles) FROM users WHERE username = 'your_username');
```

### Performance Issues

#### Symptoms
- Slow API response times
- High latency
- Timeouts
- High CPU usage

#### Diagnosis
```bash
# Check response times
curl -o /dev/null -s -w "%{time_total}\n" https://security.yourdomain.com/health

# Check CPU usage
kubectl top pods -n security-monitoring

# Check memory usage
kubectl top pods -n security-monitoring | awk '{print $4}'

# Check application metrics
curl -s http://localhost:9090/metrics | grep -E "(http_request_duration|cpu_usage|memory_usage)"
```

#### Solutions

**1. Database Query Optimization**
```sql
-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
SELECT pg_reload_conf();

-- Identify slow queries
SELECT query, calls, total_time, mean_time 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Add appropriate indexes
CREATE INDEX CONCURRENTLY idx_events_timestamp ON events(timestamp);
CREATE INDEX CONCURRENTLY idx_events_type ON events(event_type);
```

**2. Application Performance**
```rust
// Add performance monitoring
use tracing::span;

#[tracing::instrument]
async fn process_event(event: Event) -> Result<()> {
    let span = span!(Level::INFO, "process_event", event_id = %event.id);
    let _enter = span.enter();
    
    // Processing logic
    Ok(())
}
```

**3. Resource Scaling**
```yaml
# k8s/deployment.yaml
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: security-monitoring
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

### Memory Issues

#### Symptoms
- Out of Memory (OOM) errors
- High memory usage
- Pod restarts
- Memory leaks

#### Diagnosis
```bash
# Check memory usage
kubectl top pods -n security-monitoring

# Check for OOM events
kubectl describe pod <pod-name> -n security-monitoring | grep -i oom

# Monitor memory over time
kubectl top pods -n security-monitoring --watch

# Check application memory metrics
curl -s http://localhost:9090/metrics | grep memory_usage
```

#### Solutions

**1. Memory Leak Detection**
```bash
# Use heaptrack for memory profiling
heaptrack /usr/local/bin/exploit_detector

# Use Valgrind for memory analysis
valgrind --leak-check=full /usr/local/bin/exploit_detector

# Check Rust memory usage
cargo build --release
valgrind --tool=massif ./target/release/exploit_detector
```

**2. Configuration Optimization**
```yaml
# config/config.yaml
analytics:
  event_buffer_size: 10000  # Reduce if memory constrained

database:
  max_connections: 10       # Reduce connection pool size
```

**3. Code Optimization**
```rust
// Use efficient data structures
use std::collections::HashMap;
use bytes::Bytes;  // For large data blobs

// Avoid unnecessary allocations
fn process_events(events: &[Event]) -> Result<()> {
    // Process events without cloning
    for event in events {
        // Processing logic
    }
    Ok(())
}
```

### Network Issues

#### Symptoms
- Connection timeouts
- Network unreachable
- DNS resolution failures
- High latency

#### Diagnosis
```bash
# Test network connectivity
./scripts/validate-network.sh

# Check DNS resolution
kubectl exec -it <app-pod> -n security-monitoring -- nslookup postgres

# Test service connectivity
kubectl exec -it <app-pod> -n security-monitoring -- wget -qO- http://postgres:5432

# Check network policies
kubectl get networkpolicy -n security-monitoring
```

#### Solutions

**1. Network Policy Configuration**
```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: security-monitoring-netpol
  namespace: security-monitoring
spec:
  podSelector:
    matchLabels:
      app: security-monitoring
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

**2. Service Discovery**
```bash
# Verify service endpoints
kubectl get endpoints -n security-monitoring

# Test service connectivity within cluster
kubectl exec -it <app-pod> -n security-monitoring -- curl http://security-monitoring:8443/health
```

**3. DNS Configuration**
```yaml
# k8s/coredns-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
          pods insecure
          fallthrough in-addr.arpa ip6.arpa
        }
        prometheus :9153
        forward . /etc/resolv.conf
        cache 30
        loop
        reload
        loadbalance
    }
```

### Kubernetes Issues

#### Symptoms
- Pods stuck in pending state
- Image pull failures
- Persistent volume issues
- Resource quota exceeded

#### Diagnosis
```bash
# Check pod status
kubectl get pods -n security-monitoring -o wide

# Describe pod for detailed information
kubectl describe pod <pod-name> -n security-monitoring

# Check events
kubectl get events -n security-monitoring --sort-by='.lastTimestamp'

# Check resource quotas
kubectl get resourcequota -n security-monitoring
```

#### Solutions

**1. Image Pull Issues**
```bash
# Check image pull secrets
kubectl get secrets -n security-monitoring | grep image

# Create image pull secret if needed
kubectl create secret docker-registry regcred \
  --docker-server=<your-registry-server> \
  --docker-username=<your-name> \
  --docker-password=<your-pword> \
  --docker-email=<your-email> \
  -n security-monitoring

# Update service account to use image pull secret
kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "regcred"}]}' -n security-monitoring
```

**2. Persistent Volume Issues**
```bash
# Check persistent volume claims
kubectl get pvc -n security-monitoring

# Check persistent volumes
kubectl get pv -n security-monitoring

# Check storage classes
kubectl get storageclass

# Describe PVC for events
kubectl describe pvc <pvc-name> -n security-monitoring
```

**3. Resource Quotas**
```bash
# Check current resource usage
kubectl describe resourcequota -n security-monitoring

# Request quota increase if needed
kubectl edit resourcequota <quota-name> -n security-monitoring
```

## Diagnostic Tools

### Built-in Scripts

The system includes several diagnostic scripts:

- `./scripts/validate-config.sh` - Validate configuration files
- `./scripts/validate-db-connections.sh` - Test database connectivity
- `./scripts/validate-network.sh` - Test network connectivity
- `./scripts/validate-ports.sh` - Validate port assignments
- `./scripts/validate-security.sh` - Check security configuration
- `./scripts/validate-resilience.sh` - Test resilience patterns
- `./scripts/verify-deployment.sh` - Comprehensive deployment verification

### Kubernetes Debugging Tools

```bash
# Port forwarding for local access
kubectl port-forward -n security-monitoring svc/security-monitoring 8443:8443

# Debug container
kubectl debug -it <pod-name> -n security-monitoring --image=busybox --target=security-monitoring

# Copy files from pod
kubectl cp <pod-name>:/path/to/file ./local-file -n security-monitoring

# Execute commands in pod
kubectl exec -it <pod-name> -n security-monitoring -- /bin/bash
```

### Performance Profiling Tools

```bash
# CPU profiling
perf record -g ./target/release/exploit_detector
perf report

# Memory profiling
valgrind --tool=massif ./target/release/exploit_detector
ms_print massif.out.12345

# Network profiling
tcpdump -i any -w capture.pcap port 8443
wireshark capture.pcap
```

## Log Analysis

### Centralized Logging

```bash
# View all logs
kubectl logs -n security-monitoring deployment/security-monitoring -f

# View logs from specific time
kubectl logs -n security-monitoring deployment/security-monitoring --since=1h

# Filter logs by container
kubectl logs -n security-monitoring deployment/security-monitoring -c security-monitoring
```

### Log Patterns to Monitor

```bash
# Error patterns
grep -E "(ERROR|FATAL|PANIC)" logs/security-monitoring.log

# Database connection issues
grep -E "(connection.*refused|authentication.*failed|timeout)" logs/security-monitoring.log

# Memory issues
grep -E "(out of memory|OOM|allocation.*failed)" logs/security-monitoring.log

# Security events
grep -E "(authentication|authorization|security|threat)" logs/security-audit.log
```

### Log Analysis Tools

```bash
# Use jq for structured log analysis
cat logs/security-monitoring.log | jq 'select(.level == "ERROR")'

# Use awk for text log analysis
awk '/ERROR/ {print $1, $2, $7}' logs/security-monitoring.log | sort | uniq -c

# Use grep for pattern matching
grep -A 5 -B 5 "database.*timeout" logs/security-monitoring.log
```

## Performance Profiling

### Application Profiling

```rust
// Add profiling to your application
use profiling::profiler;

#[profiler::profile]
async fn handle_request(request: Request) -> Response {
    // Request handling logic
}

// Enable profiling in main.rs
fn main() {
    profiling::register_thread!("main");
    // Application logic
}
```

### Database Profiling

```sql
-- Enable query logging
ALTER SYSTEM SET log_min_duration_statement = '1000';
SELECT pg_reload_conf();

-- Create profiling view
CREATE VIEW query_stats AS
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    stddev_time,
    min_time,
    max_time,
    rows,
    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
FROM pg_stat_statements
ORDER BY total_time DESC;
```

### Network Profiling

```bash
# Monitor network connections
ss -tulpn | grep :8443

# Monitor network traffic
iftop -i eth0

# Capture network packets
tcpdump -i eth0 -w capture.pcap port 8443
```

## Emergency Procedures

### Service Outage

1. **Assess the Situation**
```bash
# Check service status
kubectl get pods -n security-monitoring

# Check health endpoints
curl -s https://security.yourdomain.com/health | jq .

# Check recent errors
kubectl get events -n security-monitoring --sort-by='.lastTimestamp' | tail -20
```

2. **Restart Services**
```bash
# Restart deployment
kubectl rollout restart deployment/security-monitoring -n security-monitoring

# Roll back to previous version
kubectl rollout undo deployment/security-monitoring -n security-monitoring
```

3. **Scale Resources**
```bash
# Scale up replicas
kubectl scale deployment/security-monitoring --replicas=5 -n security-monitoring

# Increase resource limits
kubectl edit deployment/security-monitoring -n security-monitoring
```

### Security Incident

1. **Isolate Affected Systems**
```bash
# Scale down affected services
kubectl scale deployment/security-monitoring --replicas=0 -n security-monitoring

# Block malicious IPs
kubectl annotate networkpolicy security-monitoring-netpol \
  net.beta.kubernetes.io/network-policy="" \
  -n security-monitoring
```

2. **Collect Evidence**
```bash
# Export logs
kubectl logs deployment/security-monitoring -n security-monitoring > incident-logs.txt

# Export metrics
curl -s http://localhost:9090/metrics > incident-metrics.txt

# Create backup
./scripts/backup.sh
```

3. **Restore Services**
```bash
# Restore from backup
kubectl apply -f k8s/backup/

# Scale up services gradually
kubectl scale deployment/security-monitoring --replicas=1 -n security-monitoring

# Monitor for issues
kubectl get pods -n security-monitoring -w
```

### Data Corruption

1. **Identify Corruption**
```bash
# Check database consistency
kubectl exec -it <postgres-pod> -n security-monitoring -- psql -c "VACUUM VERBOSE;"

# Check table integrity
kubectl exec -it <postgres-pod> -n security-monitoring -- psql -c "SELECT * FROM pg_stat_all_tables WHERE n_dead_tup > 0;"
```

2. **Restore from Backup**
```bash
# Restore database
kubectl exec -it <postgres-pod> -n security-monitoring -- psql -d security_monitoring -f /backups/latest.sql

# Verify restoration
kubectl exec -it <postgres-pod> -n security-monitoring -- psql -d security_monitoring -c "SELECT COUNT(*) FROM events;"
```

3. **Prevent Future Corruption**
```bash
# Enable WAL archiving
kubectl exec -it <postgres-pod> -n security-monitoring -- psql -c "ALTER SYSTEM SET archive_mode = 'on';"

# Increase checkpoint frequency
kubectl exec -it <postgres-pod> -n security-monitoring -- psql -c "ALTER SYSTEM SET checkpoint_timeout = '5min';"
```

## Getting Help

If you're unable to resolve an issue using this guide, please:

1. **Check the GitHub Issues** - Search for similar problems
2. **Create a New Issue** - Include:
   - Environment details (OS, Kubernetes version, etc.)
   - Complete error messages and logs
   - Steps to reproduce the issue
   - What you've already tried
3. **Contact Support** - For enterprise customers, contact the support team

Remember to never include sensitive information like passwords, tokens, or private keys in public issues.
```

## Benefits of This Approach

1. **Comprehensive Documentation**: Updated documentation reflecting all architectural changes
2. **Automated Verification**: Scripts to automatically verify deployment success
3. **Systematic Troubleshooting**: Structured approach to diagnosing and resolving issues
4. **Emergency Procedures**: Clear steps for handling critical failures
5. **Performance Guidance**: Tools and techniques for performance optimization
6. **Security Best Practices**: Security-focused troubleshooting procedures

## Implementation Steps

1. [ ] Update main README.md with comprehensive documentation
2. [ ] Create deployment verification script
3. [ ] Create comprehensive troubleshooting guide
4. [ ] Update all other documentation files to reflect changes
5. [ ] Test documentation and scripts in development environment
6. [ ] Validate deployment verification in staging
7. [ ] Deploy updated documentation to production
8. [ ] Train team on new troubleshooting procedures
9. [ ] Establish regular documentation review process
10. [ ] Create feedback mechanism for documentation improvements
