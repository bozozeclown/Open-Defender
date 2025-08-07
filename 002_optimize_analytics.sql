-- Create optimized indexes for analytics queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_composite ON events(event_type, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_severity ON events(severity) WHERE severity IN ('high', 'critical');

-- Create materialized view for recent security events
DROP MATERIALIZED VIEW IF EXISTS recent_security_events;
CREATE MATERIALIZED VIEW recent_security_events AS
SELECT 
    event_id,
    event_type,
    timestamp,
    source,
    data->>'severity' as severity,
    data->>'src_ip' as src_ip,
    data->>'dst_ip' as dst_ip
FROM events
WHERE timestamp > NOW() - INTERVAL '1 hour'
AND (event_type = 'network' OR event_type = 'process')
WITH DATA;

-- Create index for materialized view
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_recent_events_timestamp ON recent_security_events(timestamp DESC);

-- Create function to refresh materialized view
CREATE OR REPLACE FUNCTION refresh_recent_security_events()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY recent_security_events;
END;
$$ LANGUAGE plpgsql;

-- Create scheduled refresh instead of trigger-based
CREATE EXTENSION IF NOT EXISTS pg_cron;
SELECT cron.schedule('refresh-security-events', '*/5 * * * *', $$SELECT refresh_recent_security_events()$$);

-- Create partitioned table for large-scale event storage
DROP TABLE IF EXISTS events_partitioned CASCADE;
CREATE TABLE events_partitioned (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    source VARCHAR(100) NOT NULL,
    data JSONB NOT NULL
) PARTITION BY RANGE (timestamp);

-- Add index for partitioned table
CREATE INDEX idx_events_partitioned_type ON events_partitioned(event_type);

-- Create initial partitions
CREATE TABLE IF NOT EXISTS events_2023_q1 PARTITION OF events_partitioned
    FOR VALUES FROM ('2023-01-01') TO ('2023-04-01');
    
CREATE TABLE IF NOT EXISTS events_2023_q2 PARTITION OF events_partitioned
    FOR VALUES FROM ('2023-04-01') TO ('2023-07-01');

-- Create future partitions
CREATE TABLE IF NOT EXISTS events_2023_q3 PARTITION OF events_partitioned
    FOR VALUES FROM ('2023-07-01') TO ('2023-10-01');
    
CREATE TABLE IF NOT EXISTS events_2023_q4 PARTITION OF events_partitioned
    FOR VALUES FROM ('2023-10-01') TO ('2024-01-01');

-- Automate partition creation
CREATE OR REPLACE FUNCTION create_partition()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_tables 
        WHERE tablename = 'events_' || to_char(NEW.timestamp, 'YYYY_Q"Q"')
    ) THEN
        EXECUTE format('CREATE TABLE events_%s PARTITION OF events_partitioned 
                       FOR VALUES FROM (%L) TO (%L)', 
                       to_char(NEW.timestamp, 'YYYY_Q"Q"'),
                       date_trunc('quarter', NEW.timestamp),
                       date_trunc('quarter', NEW.timestamp) + interval '3 months');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for automatic partition creation
CREATE TRIGGER trigger_create_partition
    BEFORE INSERT ON events_partitioned
    FOR EACH ROW
    EXECUTE FUNCTION create_partition();