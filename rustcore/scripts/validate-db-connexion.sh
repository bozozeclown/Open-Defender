#!/bin/bash
# scripts/validate-db-connections.sh

set -e

ENVIRONMENT=${1:-development}

echo "Validating database connections for environment: $ENVIRONMENT"

# Load environment variables
if [ -f ".env.$ENVIRONMENT" ]; then
    source ".env.$ENVIRONMENT"
elif [ -f ".env" ]; then
    source ".env"
fi

# Check required environment variables
if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL environment variable is not set"
    exit 1
fi

# Parse database URL
DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\).*/\1/p')
DB_PORT=$(echo $DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')

echo "Testing connection to $DB_HOST:$DB_PORT database: $DB_NAME"

# Test primary database connection
if ! pg_isready -h $DB_HOST -p $DB_PORT -d $DB_NAME; then
    echo "ERROR: Cannot connect to primary database"
    exit 1
fi

echo "Primary database connection successful"

# Test read replicas if configured
if [ -n "$DB_READ_REPLICAS" ]; then
    IFS=',' read -ra REPLICAS <<< "$DB_READ_REPLICAS"
    for replica in "${REPLICAS[@]}"; do
        REPLICA_HOST=$(echo $replica | cut -d: -f1)
        REPLICA_PORT=$(echo $replica | cut -d: -f2)
        
        echo "Testing connection to replica $REPLICA_HOST:$REPLICA_PORT"
        
        if ! pg_isready -h $REPLICA_HOST -p $REPLICA_PORT -d $DB_NAME; then
            echo "WARNING: Cannot connect to replica $REPLICA_HOST:$REPLICA_PORT"
        else
            echo "Replica $REPLICA_HOST:$REPLICA_PORT connection successful"
        fi
    done
fi

echo "Database connection validation completed successfully"