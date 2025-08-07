#!/bin/bash

# Backup script for security monitoring system

BACKUP_DIR="/backups/security-monitoring"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="security_monitoring"

# Create backup directory
mkdir -p "$BACKUP_DIR/$DATE"

# Database backup
log "Starting database backup..."
docker exec postgres pg_dump -U postgres "$DB_NAME" > "$BACKUP_DIR/$DATE/database.sql"
log "Database backup completed"

# Configuration backup
log "Backing up configuration..."
cp -r /app/config "$BACKUP_DIR/$DATE/"
log "Configuration backup completed"

# Logs backup
log "Backing up logs..."
cp -r /var/log/security-monitoring "$BACKUP_DIR/$DATE/"
log "Logs backup completed"

# Compress backup
log "Compressing backup..."
tar -czf "$BACKUP_DIR/backup_$DATE.tar.gz" -C "$BACKUP_DIR" "$DATE"
rm -rf "$BACKUP_DIR/$DATE"
log "Backup compressed"

# Remove old backups (keep last 7 days)
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +7 -delete
log "Old backups removed"

log "Backup process completed"