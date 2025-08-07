# Security Monitoring System Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Security Monitoring System in production environments. The system is designed to be highly available, secure, and scalable.

## Prerequisites

### System Requirements
- **CPU**: 8+ cores recommended for production
- **Memory**: 16GB+ RAM recommended for production
- **Storage**: 100GB+ SSD storage with high IOPS
- **Network**: 10Gbps+ network connection with low latency
- **OS**: Ubuntu 20.04 LTS or RHEL 8+

### Software Requirements
- Docker 20.10+
- Docker Compose 2.0+
- Kubernetes 1.25+ (for K8s deployment)
- Helm 3.0+ (for Helm deployment)
- PostgreSQL 14+
- Redis 7+
- Vault 1.10+

### Infrastructure Requirements
- Load balancer with SSL termination
- DNS management
- SSL certificates (wildcard recommended)
- Monitoring system (Prometheus + Grafana)
- Log aggregation system
- Backup storage (S3-compatible)

## Deployment Options

### 1. Docker Compose (Recommended for small to medium deployments)

#### Quick Start
```bash
# Clone repository
git clone https://github.com/your-org/security-monitoring.git
cd security-monitoring

# Set environment variables
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
export REDIS_PASSWORD=$(openssl rand -base64 32)
export JWT_SECRET=$(openssl rand -base64 32)
export VAULT_TOKEN=$(openssl rand -base64 32)
export GRAFANA_PASSWORD=$(openssl rand -base64 32)
export DATABASE_URL="postgresql://postgres:${POSTGRES_PASSWORD}@postgres:5432/security_monitoring?sslmode=require"
export REDIS_URL="redis://:${REDIS_PASSWORD}@redis:6379"

# Create secrets directories
mkdir -p secrets
echo "${POSTGRES_PASSWORD}" > secrets/postgres_password.txt
echo "${REDIS_PASSWORD}" > secrets/redis_password.txt

# Generate SSL certificates
./scripts/generate-certs.sh

# Deploy
./scripts/deploy.sh production
```

#### Production Deployment
```bash
# Production deployment with all services
docker-compose -f docker-compose.yml up -d

# Verify deployment
docker-compose ps
docker-compose logs security-monitoring

# Check health
curl -k https://localhost/health
```

### 2. Kubernetes (Recommended for large deployments)

#### Prerequisites
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm
```

#### Deployment Steps
```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Create secrets
kubectl create secret generic security-monitoring-secrets \
  --from-literal=jwt-secret=${JWT_SECRET} \
  --from-literal=database-password=${POSTGRES_PASSWORD} \
  --from-literal=redis-password=${REDIS_PASSWORD} \
  --from-literal=vault-token=${VAULT_TOKEN} \
  --from-literal=grafana-password=${GRAFANA_PASSWORD} \
  -n security-monitoring

# Create TLS secrets
kubectl create secret tls security-monitoring-tls \
  --cert=certs/tls.crt \
  --key=certs/tls.key \
  -n security-monitoring

# Apply configurations
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/security.yaml
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/ingress.yaml

# Verify deployment
kubectl get all -n security-monitoring
kubectl get pods -n security-monitoring -w
```

### 3. Helm Deployment (Recommended for enterprise deployments)

#### Install Chart
```bash
# Add Helm repository
helm repo add security-monitoring https://charts.yourdomain.com
helm repo update

# Install release
helm install security-monitoring security-monitoring/security-monitoring \
  --namespace security-monitoring \
  --create-namespace \
  --set global.environment=production \
  --set database.password=${POSTGRES_PASSWORD} \
  --set redis.password=${REDIS_PASSWORD} \
  --set security.jwtSecret=${JWT_SECRET} \
  --set monitoring.grafana.adminPassword=${GRAFANA_PASSWORD}
```

## Configuration

### Environment Variables
| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENVIRONMENT` | Deployment environment | `development` | Yes |
| `DATABASE_URL` | PostgreSQL connection string | - | Yes |
| `REDIS_URL` | Redis connection string | - | Yes |
| `JWT_SECRET` | JWT signing secret | - | Yes |
| `VAULT_TOKEN` | Vault authentication token | - | Yes |
| `GRAFANA_PASSWORD` | Grafana admin password | - | Yes |
| `RUST_LOG` | Rust logging level | `info` | No |
| `TLS_CERT_PATH` | Path to TLS certificate | `/etc/ssl/certs/server.crt` | No |
| `TLS_KEY_PATH` | Path to TLS private key | `/etc/ssl/private/server.key` | No |

### Configuration Files
- `config/config.yaml` - Main configuration
- `config/production.yaml` - Production overrides
- `config/development.yaml` - Development settings
- `config/ports.yaml` - Port assignments
- `config/services.yaml` - Service definitions

## Security Considerations

### Network Security
1. **Network Segmentation**: Use separate networks for different service tiers
2. **Firewall Rules**: Restrict access to internal services
3. **TLS Encryption**: Encrypt all traffic in transit
4. **Authentication**: Require authentication for all external services

### Container Security
1. **Non-root Users**: Run containers as non-root users
2. **Read-only Filesystems**: Use read-only filesystems where possible
3. **Capability Dropping**: Drop unnecessary Linux capabilities
4. **Security Scanning**: Scan images for vulnerabilities

### Data Security
1. **Encryption at Rest**: Encrypt sensitive data
2. **Secrets Management**: Use Vault for secrets management
3. **Access Control**: Implement RBAC for access control
4. **Audit Logging**: Enable comprehensive audit logging

## Monitoring and Observability

### Metrics Collection
- **Application Metrics**: Exposed on port 9090
- **Database Metrics**: PostgreSQL exporter on port 9187
- **Cache Metrics**: Redis exporter on port 9121
- **System Metrics**: Node exporter on port 9100

### Logging
- **Application Logs**: Structured JSON logging
- **Access Logs**: Nginx access logs
- **Audit Logs**: Security event logging
- **Error Logs**: Error tracking and alerting

### Tracing
- **Distributed Tracing**: Jaeger integration
- **Request Tracing**: End-to-end request tracing
- **Performance Monitoring**: Latency and throughput metrics

## Backup and Recovery

### Database Backup
```bash
# Create backup
docker exec postgres pg_dump -U postgres security_monitoring > backup.sql

# Restore backup
docker exec -i postgres psql -U postgres security_monitoring < backup.sql
```

### Configuration Backup
```bash
# Backup configuration
tar -czf config-backup-$(date +%Y%m%d).tar.gz config/

# Restore configuration
tar -xzf config-backup-20230101.tar.gz
```

### Disaster Recovery
1. **Regular Backups**: Daily automated backups
2. **Off-site Storage**: Store backups in multiple locations
3. **Recovery Testing**: Regularly test recovery procedures
4. **Documentation**: Maintain up-to-date recovery documentation

## Troubleshooting

### Common Issues

#### Service Not Starting
```bash
# Check logs
docker-compose logs security-monitoring
kubectl logs -n security-monitoring deployment/security-monitoring

# Check health
curl -k https://localhost/health
kubectl get pods -n security-monitoring
```

#### Database Connection Issues
```bash
# Test database connection
docker exec -it postgres psql -U postgres -d security_monitoring

# Check database logs
docker-compose logs postgres
kubectl logs -n security-monitoring deployment/postgres
```

#### High Memory Usage
```bash
# Check memory usage
docker stats
kubectl top pods -n security-monitoring

# Adjust memory limits
# Update docker-compose.yml or k8s/deployment.yaml
```

### Performance Tuning

#### Database Optimization
1. **Index Optimization**: Regularly analyze and optimize indexes
2. **Query Optimization**: Monitor and optimize slow queries
3. **Connection Pooling**: Tune connection pool settings
4. **Read Replicas**: Use read replicas for scaling

#### Application Optimization
1. **Caching**: Implement effective caching strategies
2. **Batch Processing**: Use batch processing for bulk operations
3. **Async Processing**: Use async processing for long-running tasks
4. **Resource Limits**: Set appropriate resource limits

## Maintenance

### Regular Tasks
1. **Security Updates**: Apply security patches regularly
2. **Log Rotation**: Rotate and archive logs
3. **Database Maintenance**: Run VACUUM and ANALYZE
4. **Certificate Renewal**: Renew SSL certificates before expiry

### Scaling
1. **Horizontal Scaling**: Add more instances
2. **Vertical Scaling**: Increase resource limits
3. **Database Scaling**: Add read replicas
4. **Cache Scaling**: Add Redis nodes

## Support

### Getting Help
- **Documentation**: Check the latest documentation
- **Issues**: Report issues on GitHub
- **Community**: Join our community channels
- **Support**: Contact support for enterprise customers

### Known Limitations
1. **Database Connections**: Limited by PostgreSQL connection limits
2. **Memory Usage**: High memory usage under heavy load
3. **Network Latency**: Sensitive to network latency
4. **Storage Performance**: Requires high-performance storage

## Appendix

### Port Reference
| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| GraphQL API | 8000 | HTTPS | API endpoint |
| WebSocket | 8001 | HTTPS | Real-time updates |
| Metrics | 9090 | HTTPS | Prometheus metrics |
| Health | 8080 | HTTPS | Health checks |
| PostgreSQL | 5432 | TCP | Database |
| Redis | 6379 | TCP | Cache |
| Grafana | 3000 | HTTPS | Dashboards |
| Jaeger | 16686 | HTTPS | Tracing UI |

### Configuration Reference
See the individual configuration files for detailed configuration options.
```

#### **docs/NETWORK_TOPOLOGY.md**
```markdown
# Network Topology Documentation

## Overview

This document describes the network topology and communication patterns for the Security Monitoring System. The system is designed with security and scalability in mind, using network segmentation and secure communication channels.

## Network Architecture

### Network Segmentation

The system is divided into four main network segments:

1. **Frontend Network**: Handles external traffic and user-facing services
2. **Backend Network**: Internal communication between application and data services
3. **Monitoring Network**: Dedicated to monitoring and observability services
4. **Storage Network**: Used for database and storage services

### Network Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet                                │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          │ HTTPS (443)
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                      Load Balancer                              │
│                      (NGINX)                                    │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          │ HTTPS (8443)
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                   Frontend Network                              │
│                 (security-frontend)                            │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Security      │  │   Monitoring    │  │   Development   │ │
│  │   Monitoring    │  │   Services      │  │   Services      │ │
│  │   Service       │  │                 │  │                 │ │
│  │                 │  │                 │  │                 │ │
│  │ Ports:          │  │ Ports:          │  │ Ports:          │ │
│  │ - 8000 (HTTPS)  │  │ - 3000 (HTTPS)  │  │ - 5858 (HTTP)   │ │
│  │ - 8001 (HTTPS)  │  │ - 16686 (HTTPS) │  │ - 35729 (HTTP)  │ │
│  │ - 9090 (HTTPS)  │  │ - 9091 (HTTPS)  │  │                 │ │
│  │ - 8080 (HTTP)   │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          │ Internal (8000, 8001, 9090)
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                   Backend Network                               │
│                 (security-backend)                             │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Security      │  │   Database      │  │   Cache         │ │
│  │   Monitoring    │  │   Services      │  │   Services      │ │
│  │   Service       │  │                 │  │                 │ │
│  │                 │  │                 │  │                 │ │
│  │ Ports:          │  │ Ports:          │  │ Ports:          │ │
│  │ - 8000 (HTTP)   │  │ - 5432 (TCP)    │  │ - 6379 (TCP)    │ │
│  │ - 8001 (HTTP)   │  │ - 5433 (TCP)    │  │ - 9121 (HTTP)   │ │
│  │ - 9090 (HTTP)   │  │ - 5434 (TCP)    │  │                 │ │
│  │ - 8080 (HTTP)   │  │ - 9187 (HTTP)   │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          │ Internal (5432, 6379, 8200)
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                   Storage Network                               │
│                 (security-storage)                             │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   PostgreSQL    │  │   Redis         │  │   Vault         │ │
│  │   Primary       │  │   Cluster       │  │   Cluster       │ │
│  │                 │  │                 │  │                 │ │
│  │ Ports:          │  │ Ports:          │  │ Ports:          │ │
│  │ - 5432 (TCP)    │  │ - 6379 (TCP)    │  │ - 8200 (HTTPS)  │ │
│  │                 │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          │ Internal (9100, 8080, 9187, 9121)
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│                  Monitoring Network                             │
│                (security-monitoring)                           │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Prometheus    │  │   Grafana       │  │   Jaeger        │ │
│  │   Server        │  │   Dashboard     │  │   Tracing       │ │
│  │                 │  │                 │  │                 │ │
│  │ Ports:          │  │ Ports:          │  │ Ports:          │ │
│  │ - 9091 (HTTP)   │  │ - 3000 (HTTPS)  │  │ - 16686 (HTTPS) │ │
│  │ - 9090 (HTTP)   │  │                 │  │ - 14268 (HTTP)  │ │
│  │                 │  │                 │  │ - 6831 (UDP)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Node          │  │   cAdvisor      │  │   Alertmanager  │ │
│  │   Exporter      │  │   Container     │  │   Alerts        │ │
│  │                 │  │   Metrics       │  │                 │ │
│  │ Ports:          │  │ Ports:          │  │ Ports:          │ │
│  │ - 9100 (HTTP)   │  │ - 8080 (HTTP)   │  │ - 9093 (HTTP)   │ │
│  │                 │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Service Communication Patterns

### Application to Database
```
Security Monitoring Service ──┐
├── PostgreSQL Primary:5432
├── PostgreSQL Replica 1:5433
└── PostgreSQL Replica 2:5434
```

**Protocol**: PostgreSQL wire protocol  
**Encryption**: TLS 1.3  
**Authentication**: SCRAM-SHA-256  
**Connection Pooling**: PgBouncer (optional)

### Application to Cache
```
Security Monitoring Service ── Redis:6379
```

**Protocol**: RESP (Redis Serialization Protocol)  
**Encryption**: TLS 1.3  
**Authentication**: AUTH command with password  
**Connection Pooling**: Built-in connection pooling

### Monitoring to Application
```
Prometheus ── Security Monitoring Service:9090
Grafana ── Prometheus:9090
Jaeger ── Security Monitoring Service:8000 (tracing)
```

**Protocol**: HTTP/HTTPS  
**Authentication**: Bearer token  
**Encryption**: TLS 1.3  
**Scraping Interval**: 15 seconds

### Internal Service Communication
```
All services ── Vault:8200 (for secrets)
```

**Protocol**: HTTP/HTTPS  
**Authentication**: Token-based  
**Encryption**: TLS 1.3  
**Connection**: Persistent with keep-alive

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

## Network Security

### Firewall Rules

#### Inbound Rules
| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Internet | Load Balancer | 443 | TCP | HTTPS |
| Internet | Load Balancer | 80 | TCP | HTTP (redirect) |
| Load Balancer | Security Monitoring | 8443 | TCP | Application |
| Security Monitoring | PostgreSQL | 5432 | TCP | Database |
| Security Monitoring | Redis | 6379 | TCP | Cache |
| Prometheus | Security Monitoring | 9090 | TCP | Metrics |
| Grafana | Prometheus | 9091 | TCP | Metrics |
| Jaeger | Security Monitoring | 8000 | TCP | Tracing |

#### Outbound Rules
| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Security Monitoring | PostgreSQL | 5432 | TCP | Database |
| Security Monitoring | Redis | 6379 | TCP | Cache |
| Security Monitoring | Vault | 8200 | TCP | Secrets |
| Security Monitoring | External APIs | 443 | TCP | API calls |
| Prometheus | Security Monitoring | 9090 | TCP | Scraping |
| Grafana | Prometheus | 9091 | TCP | Data source |

### Network Policies

#### Kubernetes Network Policies
```yaml
# Allow application to access database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-to-db
spec:
  podSelector:
    matchLabels:
      app: security-monitoring
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

#### Docker Compose Network Isolation
```yaml
networks:
  security-backend:
    internal: true
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

### Security Groups

#### AWS Security Groups
```json
{
  "SecurityGroupIngress": [
    {
      "IpProtocol": "tcp",
      "FromPort": 443,
      "ToPort": 443,
      "IpRanges": ["0.0.0.0/0"]
    }
  ],
  "SecurityGroupEgress": [
    {
      "IpProtocol": "tcp",
      "FromPort": 5432,
      "ToPort": 5432,
      "IpRanges": ["172.20.0.0/24"]
    }
  ]
}
```

## Network Performance

### Bandwidth Requirements
- **Application to Database**: 1 Gbps minimum
- **Application to Cache**: 1 Gbps minimum
- **Monitoring Scraping**: 100 Mbps minimum
- **External API Calls**: 100 Mbps minimum

### Latency Requirements
- **Application to Database**: < 5ms
- **Application to Cache**: < 2ms
- **Monitoring Scraping**: < 10ms
- **External API Calls**: < 100ms

### Network Optimization
1. **Connection Pooling**: Reuse database and cache connections
2. **Keep-alive**: Enable TCP keep-alive for persistent connections
3. **Compression**: Enable compression for large payloads
4. **Caching**: Cache frequently accessed data

## Network Monitoring

### Metrics to Monitor
- **Network Throughput**: Bytes in/out per service
- **Connection Count**: Active connections per service
- **Latency**: Response time for network requests
- **Error Rate**: Failed network requests
- **Packet Loss**: Network packet loss percentage

### Monitoring Tools
- **Prometheus**: Network metrics collection
- **Grafana**: Network dashboards
- **Jaeger**: Network request tracing
- **Wireshark**: Network packet analysis
- **Netdata**: Real-time network monitoring

## Troubleshooting

### Common Network Issues

#### Connection Refused
```bash
# Check if service is running
docker-compose ps
kubectl get pods -n security-monitoring

# Check port accessibility
telnet localhost 5432
nc -z localhost 6379

# Check firewall rules
sudo iptables -L -n
sudo ufw status
```

#### High Latency
```bash
# Measure latency
ping postgres
ping redis

# Check network congestion
iftop
nload

# Check connection pool
docker exec security-monitoring netstat -an | grep ESTABLISHED
```

#### Packet Loss
```bash
# Test packet loss
ping -c 100 postgres
mtr postgres

# Check network errors
netstat -i
sar -n EDEV 1 10
```

### Network Diagnostics Commands
```bash
# Check listening ports
netstat -tulpn
ss -tulpn

# Check network connections
netstat -an
ss -an

# Check network statistics
netstat -s
ss -s

# Check routing table
ip route show
route -n

# Check DNS resolution
nslookup postgres
dig postgres
```

## Network Resilience

### High Availability
1. **Load Balancing**: Distribute traffic across multiple instances
2. **Failover**: Automatic failover for database and cache
3. **Redundancy**: Multiple network paths and connections
4. **Health Checks**: Regular health checks for all services

### Disaster Recovery
1. **Backup Network Configurations**: Regular backups of network configurations
2. **Documentation**: Up-to-date network documentation
3. **Testing**: Regular testing of network failover procedures
4. **Monitoring**: Comprehensive network monitoring and alerting

## Compliance

### Security Compliance
- **SOC 2**: Network security controls and monitoring
- **ISO 27001**: Network security management
- **GDPR**: Data protection and privacy
- **HIPAA**: Healthcare data protection (if applicable)

### Network Auditing
1. **Access Logs**: Log all network access attempts
2. **Change Management**: Document all network changes
3. **Vulnerability Scanning**: Regular network vulnerability scans
4. **Penetration Testing**: Annual penetration testing

## Future Enhancements

### Planned Improvements
1. **Service Mesh**: Implement Istio or Linkerd for advanced networking
2. **Multi-Region Deployment**: Deploy across multiple regions
3. **Edge Computing**: Deploy edge nodes for reduced latency
4. **5G Integration**: Support for 5G networks

### Scaling Considerations
1. **Horizontal Scaling**: Scale services horizontally
2. **Vertical Scaling**: Scale resources vertically
3. **Database Scaling**: Implement database sharding
4. **Cache Scaling**: Implement cache clustering
```

#### **docs/PORT_MANAGEMENT.md**
```markdown
# Port Management Documentation

## Overview

This document provides comprehensive guidance on port management for the Security Monitoring System. Proper port management is critical for security, performance, and operational efficiency.

## Port Assignments

### Application Ports
| Service | Port | Protocol | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|----------|---------|----------------|---------------|------------|
| GraphQL API | 8000 | HTTP/HTTPS | GraphQL API endpoint | Yes | Yes | Yes |
| WebSocket | 8001 | HTTP/HTTPS | WebSocket for real-time updates | Yes | Yes | Yes |
| Metrics | 9090 | HTTP/HTTPS | Prometheus metrics endpoint | Limited | Yes | No |
| Health | 8080 | HTTP | Health check endpoint | Limited | No | No |
| Debug | 5858 | HTTP | Debugging interface | Development only | No | No |

### Database Ports
| Service | Port | Protocol | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|----------|---------|----------------|---------------|------------|
| PostgreSQL Primary | 5432 | TCP | Database connection | No | Yes | No |
| PostgreSQL Replica 1 | 5433 | TCP | Read replica connection | No | Yes | No |
| PostgreSQL Replica 2 | 5434 | TCP | Read replica connection | No | Yes | No |
| PostgreSQL Exporter | 9187 | HTTP | Database metrics | No | No | No |

### Cache Ports
| Service | Port | Protocol | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|----------|---------|----------------|---------------|------------|
| Redis | 6379 | TCP | Cache connection | No | Yes | No |
| Redis Exporter | 9121 | HTTP | Cache metrics | No | No | No |

### Monitoring Ports
| Service | Port | Protocol | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|----------|---------|----------------|---------------|------------|
| Prometheus UI | 9091 | HTTP/HTTPS | Prometheus web interface | Yes | Yes | Yes |
| Prometheus Metrics | 9090 | HTTP | Internal metrics scraping | No | Yes | No |
| Grafana | 3000 | HTTP/HTTPS | Grafana dashboard interface | Yes | Yes | Yes |
| Jaeger UI | 16686 | HTTP/HTTPS | Jaeger tracing interface | Yes | Yes | Yes |
| Jaeger Collector | 14268 | HTTP | Jaeger collector endpoint | No | Yes | No |
| Jaeger Agent | 6831 | UDP | Jaeger agent endpoint | No | No | No |
| Node Exporter | 9100 | HTTP | System metrics | No | No | No |
| cAdvisor | 8080 | HTTP | Container metrics | No | No | No |
| Alertmanager | 9093 | HTTP | Alertmanager web interface | Limited | Yes | No |

### Security Ports
| Service | Port | Protocol | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|----------|---------|----------------|---------------|------------|
| Vault | 8200 | HTTP/HTTPS | Secrets management | No | Yes | Yes |
| OAuth Proxy | 4180 | HTTP/HTTPS | OAuth proxy | No | Yes | Yes |

### Development Ports
| Service | Port | Protocol | Purpose | External Access | Auth Required | HTTPS Only |
|---------|------|----------|---------|----------------|---------------|------------|
| Debug | 5858 | HTTP | Debugging interface | Development only | No | No |
| Hot Reload | 35729 | HTTP | Live reload for development | Development only | No | No |
| Profiler | 6060 | HTTP | Profiling interface | Development only | No | No |

## Environment-Specific Port Mappings

### Development Environment
All services are exposed on their default ports for easy access during development.

**Port Mapping:**
```
GraphQL API:        localhost:8000
WebSocket:          localhost:8001
Metrics:            localhost:9090
Health:             localhost:8080
Debug:              localhost:5858
Hot Reload:         localhost:35729
Profiler:           localhost:6060
PostgreSQL:         localhost:5432
Redis:              localhost:6379
Grafana:            localhost:3000
Jaeger:             localhost:16686
Prometheus:         localhost:9091
```

### Production Environment
Application services are exposed through HTTPS (port 443) via ingress. Internal services are not exposed externally.

**Port Mapping:**
```
GraphQL API:        security.yourdomain.com:443
WebSocket:          security.yourdomain.com:443
Metrics:            security.yourdomain.com:443
Health:             security.yourdomain.com:443
Grafana:            grafana.yourdomain.com:443
Jaeger:             jaeger.yourdomain.com:443
```

**Internal Services:**
```
PostgreSQL:         postgres:5432 (internal only)
Redis:              redis:6379 (internal only)
Vault:              vault:8200 (internal only)
Prometheus:         prometheus:9091 (internal)
```

## Port Security Guidelines

### 1. Internal Only Ports
These ports should never be exposed externally:
- Database ports (5432, 5433, 5434)
- Cache ports (6379)
- System metrics ports (9100, 8080)
- Debug ports (5858, 35729, 6060)
- Internal service ports (8200, 4180, 9187, 9121)

### 2. Authentication Required
All external-facing APIs and metrics should require authentication:
- GraphQL API (8000)
- WebSocket (8001)
- Metrics (9090)
- Grafana (3000)
- Jaeger (16686)
- Prometheus UI (9091)

### 3. HTTPS Only
All user-facing services should use HTTPS:
- GraphQL API (8000)
- WebSocket (8001)
- Grafana (3000)
- Jaeger (16686)
- Prometheus UI (9091)

### 4. Rate Limiting
Implement rate limiting for:
- GraphQL API (8000)
- WebSocket (8001)
- Metrics (9090)

### 5. Access Control Lists
Restrict access to:
- Metrics endpoints (9090) - only from monitoring networks
- Grafana (3000) - only from corporate networks
- Jaeger (16686) - only from corporate networks

## Port Validation

### Automatic Validation
The system includes automatic port conflict detection and validation:

```bash
# Run port validation
./scripts/validate-ports.sh production

# Expected output:
✓ No port conflicts found
✓ All required ports are accessible
✓ Internal ports are not exposed
✓ Authentication is configured for sensitive ports
✓ HTTPS is enforced for external services
```

### Validation Rules
1. **Port Conflicts**: No two services can use the same port
2. **Internal Ports**: Internal-only ports must not be exposed in production
3. **Authentication**: Sensitive ports must have authentication configured
4. **HTTPS**: External services must use HTTPS
5. **Firewall Rules**: Firewall rules must match port assignments

## Port Configuration Management

### Configuration Files
Port assignments are managed through configuration files:

- `config/ports.yaml` - Main port configuration
- `config/services.yaml` - Service-specific port settings
- `docker-compose.yml` - Docker port mappings
- `k8s/services.yaml` - Kubernetes service definitions

### Environment Variables
Port assignments can be overridden using environment variables:

```bash
# Override default ports
export GRAPHQL_PORT=8443
export WEBSOCKET_PORT=8444
export METRICS_PORT=9443
```

### Dynamic Configuration
Ports can be dynamically configured at runtime:

```yaml
# Dynamic port configuration
ports:
  application:
    graphql: "${GRAPHQL_PORT:-8000}"
    websocket: "${WEBSOCKET_PORT:-8001}"
    metrics: "${METRICS_PORT:-9090}"
```

## Port Troubleshooting

### Common Port Issues

#### 1. Port Already in Use
**Symptoms**: Service fails to start with "address already in use" error

**Diagnosis**:
```bash
# Check which process is using the port
sudo lsof -i :8000
sudo netstat -tulpn | grep :8000
```

**Solution**:
```bash
# Stop the conflicting process
sudo kill -9 <PID>

# Or change the port assignment
export GRAPHQL_PORT=8443
```

#### 2. Connection Refused
**Symptoms**: Unable to connect to a service port

**Diagnosis**:
```bash
# Check if service is running
docker-compose ps
kubectl get pods -n security-monitoring

# Check port accessibility
telnet localhost 8000
nc -z localhost 8000

# Check firewall rules
sudo iptables -L -n
sudo ufw status
```

**Solution**:
```bash
# Start the service
docker-compose up -d security-monitoring

# Or check firewall configuration
sudo ufw allow 8000
```

#### 3. Permission Denied
**Symptoms**: Service cannot bind to privileged port (< 1024)

**Diagnosis**:
```bash
# Check if port requires privileges
sudo netstat -tulpn | grep :80

# Check user permissions
whoami
id
```

**Solution**:
```bash
# Use non-privileged ports (recommended)
export GRAPHQL_PORT=8000

# Or run as root (not recommended)
sudo docker-compose up -d
```

#### 4. Port Not Accessible Externally
**Symptoms**: Service is running but not accessible from outside

**Diagnosis**:
```bash
# Check port binding
netstat -tulpn | grep :8000

# Check Docker port mapping
docker-compose ps

# Check Kubernetes service
kubectl get svc -n security-monitoring
```

**Solution**:
```bash
# Update Docker port mapping
ports:
  - "8000:8000"

# Or update Kubernetes service
type: LoadBalancer
```

### Port Testing Commands

#### Basic Connectivity Tests
```bash
# Test TCP connection
telnet localhost 8000
nc -z localhost 8000

# Test HTTP endpoint
curl http://localhost:8000/health
curl https://localhost:8443/health -k

# Test WebSocket connection
wscat -c ws://localhost:8001/ws
wscat -c wss://localhost:8443/ws -k
```

#### Advanced Diagnostics
```bash
# Check port usage
sudo lsof -i :8000
sudo netstat -tulpn | grep :8000
ss -tulpn | grep :8000

# Check network statistics
netstat -s
ss -s

# Check routing
ip route show
route -n

# Check DNS resolution
nslookup localhost
dig localhost
```

#### Container-Specific Tests
```bash
# Test port within container
docker exec security-monitoring netstat -tulpn
docker exec security-monitoring ss -tulpn

# Test connectivity between containers
docker exec security-monitoring nc -z postgres 5432
docker exec security-monitoring nc -z redis 6379

# Test port mapping
docker port security-monitoring
```

## Port Security Best Practices

### 1. Principle of Least Privilege
- Only expose necessary ports
- Use non-privileged ports when possible
- Implement strict access controls

### 2. Network Segmentation
- Use separate networks for different service tiers
- Implement firewall rules between network segments
- Use network policies in Kubernetes

### 3. Encryption
- Use TLS for all external services
- Use mutual TLS for internal services
- Implement certificate management

### 4. Monitoring and Logging
- Monitor port usage and connections
- Log all access attempts
- Implement alerting for suspicious activity

### 5. Regular Audits
- Regularly review port assignments
- Audit firewall rules
- Test port security controls

## Port Management Automation

### Automated Port Validation
```bash
#!/bin/bash
# scripts/validate-ports.sh

ENVIRONMENT=${1:-development}

echo "Validating port configuration for environment: $ENVIRONMENT"

# Check port conflicts
check_port_conflicts() {
    echo "Checking for port conflicts..."
    
    # Extract all port numbers from configuration
    ports=$(grep -r "port:" config/ | grep -o "[0-9]\+" | sort -n)
    
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

# Check port accessibility
check_port_accessibility() {
    echo "Checking port accessibility..."
    
    # Define ports to check based on environment
    case $ENVIRONMENT in
        "development")
            check_ports=(8000 8001 9090 8080 5432 6379 3000 16686 9091)
            ;;
        "production")
            check_ports=(443 8443 9090 8080)
            ;;
    esac
    
    for port in "${check_ports[@]}"; do
        if nc -z localhost "$port" 2>/dev/null; then
            echo "✓ Port $port is accessible"
        else
            echo "⚠ Port $port is not accessible"
        fi
    done
}

# Run validation checks
check_port_conflicts
check_port_accessibility

echo "Port validation completed"
```

### Automated Port Configuration
```yaml
# docker-compose.yml with dynamic ports
services:
  security-monitoring:
    ports:
      - "${GRAPHQL_PORT:-8000}:8000"
      - "${WEBSOCKET_PORT:-8001}:8001"
      - "${METRICS_PORT:-9090}:9090"
    environment:
      - GRAPHQL_PORT=${GRAPHQL_PORT:-8000}
      - WEBSOCKET_PORT=${WEBSOCKET_PORT:-8001}
      - METRICS_PORT=${METRICS_PORT:-9090}
```

## Port Documentation and Change Management

### Documentation Requirements
1. **Port Assignment Table**: Maintain up-to-date port assignments
2. **Network Diagrams**: Visual representation of port usage
3. **Security Guidelines**: Document port security requirements
4. **Troubleshooting Guide**: Common port issues and solutions

### Change Management Process
1. **Request**: Submit port change request
2. **Review**: Security and operations review
3. **Testing**: Test changes in staging environment
4. **Approval**: Obtain necessary approvals
5. **Implementation**: Deploy changes with rollback plan
6. **Documentation**: Update documentation
7. **Communication**: Notify stakeholders

### Change Request Template
```markdown
# Port Change Request

## Request Details
- **Requester**: [Name]
- **Date**: [Date]
- **Environment**: [Development/Staging/Production]
- **Priority**: [Low/Medium/High/Critical]

## Change Description
- **Current Port**: [Current port number]
- **New Port**: [New port number]
- **Service**: [Service name]
- **Reason for Change**: [Explanation]

## Impact Analysis
- **Affected Services**: [List of affected services]
- **Dependencies**: [List of dependencies]
- **Risk Assessment**: [Risk level and mitigation]

## Testing Plan
- **Test Environment**: [Environment for testing]
- **Test Cases**: [List of test cases]
- **Rollback Plan**: [Rollback procedure]

## Approval
- **Security Approval**: [Signature/Date]
- **Operations Approval**: [Signature/Date]
- **Final Approval**: [Signature/Date]
```

## Conclusion

Effective port management is crucial for the security and reliability of the Security Monitoring System. By following the guidelines and procedures outlined in this document, you can ensure that port assignments are secure, efficient, and well-documented.

Remember to:
- Regularly review and audit port assignments
- Implement proper security controls for all ports
- Maintain comprehensive documentation
- Use automation for validation and configuration
- Follow change management procedures for port changes

For questions or assistance with port management, please contact the operations team.
