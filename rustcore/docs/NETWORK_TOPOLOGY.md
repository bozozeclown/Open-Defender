# Network Topology Documentation

## Service Names and Ports

### Core Services
| Service Name | Container Name | Port | Purpose | Network |
|--------------|----------------|------|---------|---------|
| postgres | postgres | 5432 | Database | security-backend |
| redis | redis | 6379 | Cache | security-backend |
| security-monitoring | security-monitoring | 8000 | GraphQL API | security-backend, security-monitoring |
| security-monitoring | security-monitoring | 8001 | WebSocket | security-backend, security-monitoring |
| security-monitoring | security-monitoring | 9090 | Metrics | security-monitoring |

### Monitoring Services
| Service Name | Container Name | Port | Purpose | Network |
|--------------|----------------|------|---------|---------|
| prometheus | prometheus | 9091 | Prometheus UI | security-monitoring |
| grafana | grafana | 3000 | Grafana Dashboard | security-monitoring |
| jaeger | jaeger | 16686 | Jaeger UI | security-monitoring |

## Network Segmentation

### security-backend (Internal Network)
- **Purpose**: Internal communication between application and data services
- **Services**: postgres, redis, security-monitoring
- **Access**: Internal only, not exposed to external traffic
- **Security**: Database and cache services are isolated from external access

### security-monitoring (Monitoring Network)
- **Purpose**: Monitoring and observability services
- **Services**: security-monitoring (metrics), prometheus, grafana, jaeger
- **Access**: Limited external access for monitoring dashboards
- **Security**: Monitoring services can access application metrics

## Service Communication Patterns

### Application to Database

security-monitoring ──┐
├── postgres:5432
security-monitoring ──┘

### Application to Cache
security-monitoring ── redis:6379

### Monitoring to Application
prometheus ── security-monitoring:9090
grafana ── prometheus:9090
jaeger ── security-monitoring:8000 (tracing)

## External Access

### Production Environment
- **GraphQL API**: https://security.yourdomain.com (port 443)
- **WebSocket**: wss://security.yourdomain.com/ws (port 443)
- **Grafana**: https://grafana.yourdomain.com (port 443)
- **Jaeger**: https://jaeger.yourdomain.com (port 443)

### Development Environment
- **GraphQL API**: http://localhost:8000
- **WebSocket**: ws://localhost:8001
- **Grafana**: http://localhost:3000
- **Jaeger**: http://localhost:16686