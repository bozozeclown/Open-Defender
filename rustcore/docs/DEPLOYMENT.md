# Security Monitoring System Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Security Monitoring System in production environments.

## Prerequisites

### System Requirements
- **CPU**: 4+ cores recommended
- **Memory**: 8GB+ RAM recommended
- **Storage**: 50GB+ SSD storage
- **Network**: 1Gbps+ network connection

### Software Requirements
- Docker 20.10+
- Docker Compose 2.0+
- PostgreSQL 13+
- Redis 6+
- Kubernetes 1.20+ (for K8s deployment)

## Deployment Options

### 1. Docker Compose (Recommended for small to medium deployments)

#### Quick Start
```bash
# Clone repository
git clone https://github.com/your-org/security-monitoring.git
cd security-monitoring

# Set environment variables
export POSTGRES_PASSWORD=your-secure-password
export JWT_SECRET=your-super-secret-jwt-key

# Deploy
./scripts/deploy.sh production