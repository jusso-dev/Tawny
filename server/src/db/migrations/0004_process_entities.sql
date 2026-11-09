-- Process entities (docs/architecture/target-edr.md section 2.4). One row per
-- process, keyed by the entity id the agent computed (or the legacy
-- normaliser computed for schema 1 events). Applied as one simple-query
-- script by the migrator.

CREATE TABLE process_entities (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    agent_id uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    entity_id text NOT NULL CHECK (entity_id ~ '^[a-z2-7]{26}$'),
    parent_entity_id text CHECK (parent_entity_id IS NULL OR parent_entity_id ~ '^[a-z2-7]{26}$'),
    pid bigint NOT NULL CHECK (pid >= 0),
    image text,
    command_line text,
    user_name text,
    start_time timestamptz,
    end_time timestamptz,
    first_event_id bigint,
    PRIMARY KEY (tenant_id, entity_id)
);

CREATE INDEX process_entities_parent_idx ON process_entities (tenant_id, parent_entity_id);
CREATE INDEX process_entities_agent_pid_idx ON process_entities (tenant_id, agent_id, pid, start_time DESC);
CREATE INDEX process_entities_agent_start_idx ON process_entities (tenant_id, agent_id, start_time DESC);

ALTER TABLE process_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE process_entities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON process_entities;
CREATE POLICY tenant_isolation ON process_entities
    USING (tenant_id = tawny_current_tenant())
    WITH CHECK (tenant_id = tawny_current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON process_entities TO tawny_app, tawny_jobs;
