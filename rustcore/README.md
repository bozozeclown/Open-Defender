

# Security Monitoring System

A comprehensive, real-time security monitoring and incident response platform built with Rust, designed to detect, analyze, and respond to security threats across your infrastructure.

## Features

### 🛡️ Security Monitoring
- **Real-time Event Collection**: Monitor network traffic, process activity, file operations, and system logs
- **Advanced Threat Detection**: Port scanning, data exfiltration, suspicious processes, and file activity detection
- **Pattern Recognition**: Identify attack patterns and correlate events to detect sophisticated threats
- **Anomaly Detection**: Statistical analysis to identify unusual behavior and potential security incidents

### 🚨 Incident Response
- **Automated Response Actions**: Isolate hosts, block IPs, terminate processes, and quarantine files
- **Incident Management**: Create, assign, track, and resolve security incidents
- **Response Templates**: Pre-configured response actions for common threat scenarios
- **Audit Trail**: Complete logging of all response actions for compliance and analysis

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

## Installation

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- PostgreSQL 13+
- Redis 6+
- Jaeger (for tracing, optional)

### Quick Start

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
cargo run --release

# Or start individual services
cargo run --bin graphql-server
cargo run --bin websocket-server
cargo run --bin event-collector
```

### Docker Setup

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f
```

## Configuration

The system uses environment variables for configuration. Key configuration options:

### Database
```bash
DATABASE_URL=postgres://user:password@localhost/security_monitoring
DB_MAX_CONNECTIONS=10
```

### Analytics
```bash
EVENT_BUFFER_SIZE=10000
PORT_SCAN_THRESHOLD=50
DATA_EXFILTRATION_THRESHOLD=10485760  # 10MB
SUSPICIOUS_PROCESSES=powershell.exe,cmd.exe,wscript.exe,cscript.exe,rundll32.exe,regsvr32.exe
SYSTEM_METRICS_INTERVAL=60
```

### API
```bash
GRAPHQL_ENDPOINT=127.0.0.1:8000
JWT_SECRET=your-secret-key-here
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### Collaboration
```bash
WEBSOCKET_ENDPOINT=127.0.0.1:8001
REDIS_URL=redis://localhost:6379
```

### Observability
```bash
RUST_LOG=info
JAEGER_ENDPOINT=localhost:6831
METRICS_ENDPOINT=localhost:9090
```

## Usage

### GraphQL API

Access the GraphQL Playground at `http://localhost:8000` for interactive API exploration.

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

Connect to the WebSocket server at `ws://localhost:8001` for real-time collaboration.

#### Example Message Format

```json
{
  "type": "chat",
  "workspace_id": "workspace-123",
  "message": "Investigating the suspicious activity",
  "message_type": "text"
}
```

### Command Line Interface

```bash
# Show system status
cargo run --bin cli status

# Create an incident
cargo run --bin cli incident create --title "Test Incident" --severity "medium"

# View metrics
cargo run --bin cli metrics

# Run health checks
cargo run --bin cli health
```

## API Documentation

### GraphQL Schema

The GraphQL API provides the following main types:

#### Queries
- `events(limit, offset, event_type)`: Retrieve security events
- `incidents(status, severity)`: Get security incidents
- `analytics_metrics`: System performance metrics
- `analytics_alerts(limit, offset)`: Security alerts
- `system_health`: System health status

#### Mutations
- `createIncident(title, description, severity)`: Create new incident
- `assignIncident(id, user)`: Assign incident to user
- `closeIncident(id, resolution)`: Close incident with resolution
- `acknowledgeAlert(id)`: Acknowledge security alert
- `resolveAlert(id)`: Resolve security alert

#### Subscriptions
- `workspaceUpdated(workspace_id)`: Real-time workspace updates
- `newAlerts`: Real-time alert notifications
- `incidentUpdates(incident_id)`: Incident status updates

### REST Endpoints

- `GET /metrics`: Prometheus metrics endpoint
- `GET /health`: System health status
- `GET /health/:check`: Individual health check results

## Development

### Project Structure

```
src/
├── analytics/          # Security analytics and detection engine
├── api/               # GraphQL API server
├── collaboration/     # Real-time collaboration features
├── collectors/        # Event collection from various sources
├── config/            # Configuration management
├── error/             # Error handling and types
├── observability/     # Metrics, tracing, and logging
├── response/          # Incident response and automation
├── utils/             # Utility modules and helpers
└── main.rs           # Application entry point

tests/
├── integration/       # Integration tests
└── unit/             # Unit tests

docs/                  # Additional documentation
├── api/               # API documentation
└── deployment/        # Deployment guides
```

### Building and Testing

```bash
# Build the project
cargo build

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

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests
cargo test --test integration_tests

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Test Coverage

```bash
# Install tarpaulin for coverage
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html

# Generate coverage for specific module
cargo tarpaulin --lib -- -p analytics
```

### Performance Testing

```bash
# Run load tests
cargo run --bin load-test

# Benchmark specific functions
cargo bench
```

## Deployment

### Production Deployment

1. **Environment Setup**
```bash
# Set production environment variables
export RUST_LOG=info
export DATABASE_URL=postgres://user:pass@prod-db:5432/security_monitoring
export REDIS_URL=redis://prod-redis:6379
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
      containers:
      - name: app
        image: security-monitoring:latest
        ports:
        - containerPort: 8000
        - containerPort: 8001
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
```

### Monitoring Setup

1. **Prometheus Configuration**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'security-monitoring'
    static_configs:
      - targets: ['localhost:9090']
```

2. **Grafana Dashboards**
Import the provided dashboards from `docs/grafana/` or create custom dashboards using the available metrics.

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: Full documentation is available at [docs.example.com](https://docs.example.com)
- **Issues**: Report bugs and request features on [GitHub Issues](https://github.com/your-org/security-monitoring/issues)
- **Discussions**: Join our community discussions on [GitHub Discussions](https://github.com/your-org/security-monitoring/discussions)
- **Email**: Contact the team at security@example.com

## Acknowledgments

- [Rust](https://www.rust-lang.org/) for providing a safe and performant language
- [GraphQL](https://graphql.org/) for the powerful API specification
- [PostgreSQL](https://www.postgresql.org/) for the reliable database
- [Prometheus](https://prometheus.io/) for metrics and monitoring
- [Jaeger](https://www.jaegertracing.io/) for distributed tracing
- The open-source community for various libraries and tools

---

**Security Note**: This is a security monitoring tool. Please ensure proper security measures are in place when deploying in production environments, including proper authentication, authorization, and network security controls.