-- Agent hardening (#58): quiet agent and quiet sensor alerts, update rings,
-- update state. Applied as one simple-query script in a transaction.

-- Clean shutdown notice. Set by a heartbeat with "shutdown": true and cleared
-- by the next normal heartbeat. jobs/stale.zig raises "Agent silent" when an
-- agent goes offline while this is null.
ALTER TABLE agents ADD COLUMN clean_shutdown_at timestamptz;
ALTER TABLE agents ADD COLUMN clean_shutdown_reason text;

-- Update ring override and the last update state the agent reported in
-- agent_health. Ring is null for the default: bucket = hash(agent_id) mod 100.
ALTER TABLE agents ADD COLUMN update_ring text
    CHECK (update_ring IS NULL OR update_ring IN ('canary', 'internal', '10', '50', '100'));
ALTER TABLE agents ADD COLUMN update_state text;
ALTER TABLE agents ADD COLUMN update_version text;
ALTER TABLE agents ADD COLUMN update_state_at timestamptz;
ALTER TABLE agents ADD COLUMN key_protection text;

-- Release rings. `ring` is the widest ring the release is open to. Existing
-- rows were already offered to everyone, so they start at '100'. New rows
-- from the release sync start at 'canary' and are promoted by
-- releases.promote when the previous ring stays healthy for the soak period.
ALTER TABLE agent_releases ADD COLUMN ring text NOT NULL DEFAULT '100'
    CHECK (ring IN ('canary', 'internal', '10', '50', '100'));
ALTER TABLE agent_releases ADD COLUMN ring_opened_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE agent_releases ADD COLUMN size bigint;
ALTER TABLE agent_releases ADD COLUMN manifest text;
ALTER TABLE agent_releases ADD COLUMN manifest_signature text;

-- Per-sensor delivery, fed by sensor_health and agent_health events. The
-- quiet-sensor job alerts when a sensor that was running has delivered
-- nothing for 15 minutes while the agent itself is still heartbeating.
CREATE TABLE sensor_status (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    agent_id uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    sensor text NOT NULL CHECK (length(sensor) BETWEEN 1 AND 200),
    state text NOT NULL,
    state_since timestamptz NOT NULL,
    was_running boolean NOT NULL DEFAULT false,
    -- Continuous sensors (Sysmon, Security, the launch tracker) alert on 15
    -- minutes without events. Sparse ones (PowerShell, System 7045) only
    -- alert when they stop or fail, because a quiet hour is normal for them.
    continuous boolean NOT NULL DEFAULT false,
    last_event_at timestamptz,
    open_alert_id bigint,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, sensor)
);

ALTER TABLE sensor_status ENABLE ROW LEVEL SECURITY;
ALTER TABLE sensor_status FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON sensor_status;
CREATE POLICY tenant_isolation ON sensor_status
    USING (tenant_id = tawny_current_tenant())
    WITH CHECK (tenant_id = tawny_current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON sensor_status TO tawny_app, tawny_jobs;

-- Server-raised alerts (Agent silent, Sensor silent, Agent tamper) hang off
-- one disabled rule per tenant, found by external id.
CREATE UNIQUE INDEX alert_rules_system_idx ON alert_rules (tenant_id, external_id)
    WHERE external_id LIKE 'tawny-system:%';
CREATE INDEX alerts_open_rule_agent_idx ON alerts (tenant_id, alert_rule_id, agent_id) WHERE status = 'open';
