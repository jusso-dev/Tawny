-- Detection engine (issue #56): Sigma compile status, sequence and threshold
-- state. Applied as one simple-query script in a transaction.

-- Sigma rules keep their AST in the existing compiled_expression_json column.
-- compile_status is supported, supported_with_notes or rejected; rejected
-- rules are never stored, so the column only shows the first two today.
ALTER TABLE alert_rules ADD COLUMN compile_status text;
ALTER TABLE alert_rules ADD COLUMN compile_notes text[] NOT NULL DEFAULT '{}';

ALTER TABLE alert_rules DROP CONSTRAINT IF EXISTS alert_rules_format_check;
ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_format_check
    CHECK (format IN ('tawny_predicate', 'sigma', 'ioc', 'sequence', 'threshold', 'atomic', 'yara', 'package_exposure'));

-- Built-in rules from rules/builtin/ are seeded once per tenant and found
-- again by external_id.
CREATE UNIQUE INDEX alert_rules_builtin_idx ON alert_rules (tenant_id, external_id)
    WHERE external_id LIKE 'tawny-builtin:%';

-- Sequence state: one row per rule and `by` key. The table from 0001 was
-- never written, so it is empty and its key can change.
ALTER TABLE sequence_state DROP CONSTRAINT IF EXISTS sequence_state_pkey;
ALTER TABLE sequence_state ADD COLUMN by_key text NOT NULL DEFAULT '';
ALTER TABLE sequence_state ADD COLUMN step_count integer NOT NULL DEFAULT 0;
ALTER TABLE sequence_state ADD COLUMN started_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE sequence_state ADD COLUMN expires_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE sequence_state ADD COLUMN event_ids bigint[] NOT NULL DEFAULT '{}';
ALTER TABLE sequence_state ADD PRIMARY KEY (tenant_id, rule_id, by_key);
ALTER TABLE sequence_state ADD CONSTRAINT sequence_state_rule_fk
    FOREIGN KEY (rule_id) REFERENCES alert_rules (id) ON DELETE CASCADE;
CREATE INDEX sequence_state_expires_idx ON sequence_state (expires_at);

-- Threshold counters: one row per matching event inside the window, so the
-- window slides exactly. Rows for a key are cleared when the rule fires.
CREATE TABLE threshold_counters (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    rule_id uuid NOT NULL REFERENCES alert_rules (id) ON DELETE CASCADE,
    by_key text NOT NULL,
    value text,
    event_id bigint NOT NULL,
    occurred_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX threshold_counters_key_idx ON threshold_counters (tenant_id, rule_id, by_key, occurred_at);
CREATE INDEX threshold_counters_expires_idx ON threshold_counters (expires_at);

ALTER TABLE threshold_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE threshold_counters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON threshold_counters;
CREATE POLICY tenant_isolation ON threshold_counters
    USING (tenant_id = tawny_current_tenant())
    WITH CHECK (tenant_id = tawny_current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON threshold_counters TO tawny_app, tawny_jobs;

-- YARA (#56): the agent's on-demand yara_scan response action.
ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS response_actions_action_type_check;
ALTER TABLE response_actions ADD CONSTRAINT response_actions_action_type_check
    CHECK (action_type IN ('kill_process', 'isolate_host', 'release_host', 'yara_scan'));
