-- Create optimized indexes for analytics queries
CREATE INDEX CONCURRENTLY idx_events_composite ON events(event_type, timestamp DESC);
CREATE INDEX CONCURRENTLY idx_events_severity ON events(severity) WHERE severity IN ('high', 'critical');

-- Create materialized view for recent security events
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
CREATE INDEX idx_recent_events_timestamp ON recent_security_events(timestamp DESC);

-- Create function to refresh materialized view
CREATE OR REPLACE FUNCTION refresh_recent_security_events()
RETURNS TRIGGER AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY recent_security_events;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to refresh materialized view periodically
CREATE OR REPLACE TRIGGER trigger_refresh_recent_events
AFTER INSERT OR UPDATE ON events
FOR EACH STATEMENT
EXECUTE FUNCTION refresh_recent_security_events();

-- Create partitioned table for large-scale event storage
CREATE TABLE events_partitioned (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    source VARCHAR(100) NOT NULL,
    data JSONB NOT NULL
) PARTITION BY RANGE (timestamp);

-- Create partitions
CREATE TABLE events_2023_q1 PARTITION OF events_partitioned
    FOR VALUES FROM ('2023-01-01') TO ('2023-04-01');
    
CREATE TABLE events_2023_q2 PARTITION OF events_partitioned
    FOR VALUES FROM ('2023-04-01') TO ('2023-07-01');