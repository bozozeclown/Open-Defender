#!/bin/bash
# scripts/validate-config.sh

set -e

ENVIRONMENT=${1:-development}

echo "Validating configuration for environment: $ENVIRONMENT"

# Check if configuration files exist
if [ ! -f "config/config.yaml" ]; then
    echo "ERROR: Base configuration file not found"
    exit 1
fi

if [ ! -f "config/$ENVIRONMENT.yaml" ]; then
    echo "WARNING: Environment-specific configuration not found for $ENVIRONMENT"
fi

# Validate YAML syntax
if command -v yq &> /dev/null; then
    echo "Validating YAML syntax..."
    yq eval 'true' config/config.yaml
    if [ -f "config/$ENVIRONMENT.yaml" ]; then
        yq eval 'true' config/$ENVIRONMENT.yaml"
    fi
else
    echo "WARNING: yq not found, skipping YAML validation"
fi

# Check required environment variables
REQUIRED_VARS=("DATABASE_URL" "REDIS_URL" "JWT_SECRET")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "ERROR: Required environment variable $var is not set"
        exit 1
    fi
done

echo "Configuration validation completed successfully"