-- Single statement. The migrator sends this file as one simple query.
CREATE OR REPLACE FUNCTION tawny_purge_expired(now_ts timestamptz)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM alerts
    WHERE created_at < now_ts - interval '365 days';

    DELETE FROM telemetry_events AS te
    WHERE te.received_at < now_ts - interval '30 days'
      AND NOT EXISTS (
          SELECT 1
          FROM alerts AS a
          WHERE a.telemetry_event_id = te.id
            AND a.telemetry_received_at = te.received_at
      );
END;
$$;
