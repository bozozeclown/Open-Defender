#!/bin/bash

# Restore script for security monitoring system

BACKUP_FILE=$1
DB_NAME="security_monitoring"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Extract backup
log "Extracting backup..."
tar -xzf "$BACKUP_FILE" -C /tmp/
BACKUP_DIR=$(find /tmp -name "backup_*" -type d | head -1)

# Stop services
log "Stopping services..."
docker-compose down

# Restore database
log "Restoring database..."
docker exec -i postgres psql -U postgres "$DB_NAME" < "$BACKUP_DIR/database.sql"

# Restore configuration
log "Restoring configuration..."
cp -r "$BACKUP_DIR/config" /app/

# Restore logs
log "Restoring logs..."
cp -r "$BACKUP_DIR/logs" /var/log/security-monitoring/

# Start services
log "Starting services..."
docker-compose up -d

# Cleanup
rm -rf "$BACKUP_DIR"

log "Restore process completed"