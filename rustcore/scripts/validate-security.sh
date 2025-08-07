#!/bin/bash
# scripts/validate-security.sh

set -e

ENVIRONMENT=${1:-production}

echo "Validating security configuration for environment: $ENVIRONMENT"

# Check if secrets are properly managed
check_secrets() {
    echo "Checking secrets management..."
    
    if [ -z "$VAULT_URL" ] || [ -z "$VAULT_TOKEN" ]; then
        echo "⚠ Vault credentials not found in environment variables"
    else
        echo "✓ Vault credentials configured"
    fi
    
    # Check if sensitive files exist
    sensitive_files=("secrets/postgres_password.txt" "secrets/redis_password.txt")
    for file in "${sensitive_files[@]}"; do
        if [ -f "$file" ]; then
            if [ -r "$file" ] && [ "$(stat -c %a "$file")" != "600" ]; then
                echo "✗ Secret file $file has incorrect permissions"
                return 1
            else
                echo "✓ Secret file $file has correct permissions"
            fi
        else
            echo "✗ Secret file $file not found"
            return 1
        fi
    done
}

# Check TLS certificates
check_tls_certificates() {
    echo "Checking TLS certificates..."
    
    if [ ! -f "certs/tls.crt" ] || [ ! -f "certs/tls.key" ]; then
        echo "✗ TLS certificates not found"
        return 1
    fi
    
    # Check certificate expiration
    if command -v openssl &> /dev/null; then
        expiry=$(openssl x509 -enddate -noout -in certs/tls.crt | cut -d= -f2)
        expiry_timestamp=$(date -d "$expiry" +%s)
        current_timestamp=$(date +%s)
        days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
        
        if [ $days_until_expiry -lt 30 ]; then
            echo "⚠ Certificate expires in $days_until_expiry days"
        else
            echo "✓ Certificate is valid for $days_until_expiry more days"
        fi
    else
        echo "⚠ OpenSSL not found, skipping certificate validation"
    fi
}

# Check security headers
check_security_headers() {
    echo "Checking security headers..."
    
    if [ "$ENVIRONMENT" = "production" ]; then
        response=$(curl -s -I https://security.yourdomain.com 2>/dev/null || echo "")
        
        headers=("X-Content-Type-Options" "X-Frame-Options" "X-XSS-Protection" "Strict-Transport-Security")
        for header in "${headers[@]}"; do
            if echo "$response" | grep -qi "$header"; then
                echo "✓ Security header $header is present"
            else
                echo "✗ Security header $header is missing"
            fi
        done
    else
        echo "Skipping security headers check for non-production environment"
    fi
}

# Check network security
check_network_security() {
    echo "Checking network security..."
    
    # Check if services are properly isolated
    if docker network ls | grep -q "security-backend"; then
        echo "✓ Security backend network exists"
        
        # Check if internal services are not exposed
        internal_services=("postgres" "redis" "vault")
        for service in "${internal_services[@]}"; do
            if docker inspect "$service" | grep -q '"Ports": \[\]'; then
                echo "✓ Service $service is not exposed externally"
            else
                echo "⚠ Service $service may be exposed externally"
            fi
        done
    else
        echo "✗ Security backend network not found"
    fi
}

# Check authentication and authorization
check_auth_config() {
    echo "Checking authentication and authorization..."
    
    if [ -z "$JWT_SECRET" ]; then
        echo "✗ JWT secret not configured"
        return 1
    fi
    
    if [ ${#JWT_SECRET} -lt 32 ]; then
        echo "✗ JWT secret is too short (minimum 32 characters)"
        return 1
    fi
    
    echo "✓ JWT secret is properly configured"
}

# Check audit logging
check_audit_logging() {
    echo "Checking audit logging..."
    
    if [ ! -d "logs" ]; then
        echo "✗ Logs directory not found"
        return 1
    fi
    
    if [ ! -f "logs/security_audit.log" ]; then
        echo "⚠ Security audit log not found (will be created on first event)"
    else
        echo "✓ Security audit log exists"
    fi
}

# Run all security checks
check_secrets
check_tls_certificates
check_security_headers
check_network_security
check_auth_config
check_audit_logging

echo "Security validation completed"