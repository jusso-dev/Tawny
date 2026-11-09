-- Server analyst work (#60): analyst role, tenant settings, Entra ID sign-in,
-- incidents. Applied as one simple-query script in a transaction.

-- Analyst role (docs/api.md has the permission matrix).
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'analyst', 'viewer'));

-- Break-glass admins keep password sign-in when the tenant limits it.
ALTER TABLE users ADD COLUMN break_glass boolean NOT NULL DEFAULT false;
-- Entra ID identity: object id and tenant id from the ID token. Never email.
ALTER TABLE users ADD COLUMN oidc_tid text;
ALTER TABLE users ADD COLUMN oidc_oid text;
CREATE UNIQUE INDEX users_oidc_identity_idx ON users (oidc_tid, oidc_oid) WHERE oidc_oid IS NOT NULL;
-- The bootstrap admin is the first break-glass account.
UPDATE users SET break_glass = true WHERE role = 'admin' AND password_hash IS NOT NULL
    AND id = (SELECT id FROM users WHERE role = 'admin' ORDER BY created_at LIMIT 1);

CREATE TABLE tenant_settings (
    tenant_id uuid PRIMARY KEY REFERENCES tenants (id),
    -- 'all': every user with a password may sign in with it.
    -- 'break_glass': only admins marked break_glass may.
    password_login text NOT NULL DEFAULT 'all' CHECK (password_login IN ('all', 'break_glass')),
    -- Destructive actions (isolate, quarantine) requested by an analyst wait
    -- for an admin to approve them (target-edr section 9.2).
    analyst_destructive_needs_approval boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- One Entra ID (OIDC) configuration per Tawny tenant.
CREATE TABLE tenant_oidc (
    tenant_id uuid PRIMARY KEY REFERENCES tenants (id),
    enabled boolean NOT NULL DEFAULT false,
    entra_tenant_id text NOT NULL CHECK (length(entra_tenant_id) BETWEEN 1 AND 100),
    -- Null means https://login.microsoftonline.com/<entra_tenant_id>/v2.0.
    authority text,
    client_id text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 200),
    -- secret_box v1 ciphertext under TAWNY_INTEGRATION_ENCRYPTION_KEY.
    client_secret_encrypted text,
    allowed_domains text[] NOT NULL DEFAULT '{}',
    -- {"<group object id>": "admin" | "analyst" | "viewer"}
    group_roles jsonb NOT NULL DEFAULT '{}'::jsonb,
    discovery_json jsonb,
    jwks_json jsonb,
    jwks_fetched_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- oauth_states serves GitHub and OIDC. OIDC rows also carry the nonce and
-- the Tawny tenant the sign-in started for.
ALTER TABLE oauth_states ADD COLUMN provider text NOT NULL DEFAULT 'github';
ALTER TABLE oauth_states ADD COLUMN nonce text;
ALTER TABLE oauth_states ADD COLUMN tenant_id uuid;

-- Response approval (target-edr section 9.2, last line).
ALTER TABLE response_actions ADD COLUMN approved_by_user_id uuid;
ALTER TABLE response_actions ADD COLUMN approved_at timestamptz;

-- Alert triage.
ALTER TABLE alerts ADD COLUMN acknowledged_at timestamptz;
ALTER TABLE alerts ADD COLUMN acknowledged_by_user_id uuid;
ALTER TABLE alerts ADD COLUMN resolved_at timestamptz;
ALTER TABLE alerts ADD COLUMN resolved_by_user_id uuid;

-- Incidents (target-edr sections 7 and 8).
CREATE TABLE incidents (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    title text NOT NULL,
    status text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive')),
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    risk integer NOT NULL CHECK (risk BETWEEN 0 AND 100),
    -- [{"key","kind","label","weight","confidence","context","points"}]
    risk_items jsonb NOT NULL DEFAULT '[]'::jsonb,
    owner_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Which section 8 rule opened the incident: lineage, artefact, indicator, alert.
    grouping text NOT NULL,
    root_entity_id text,
    agent_ids uuid[] NOT NULL DEFAULT '{}',
    users text[] NOT NULL DEFAULT '{}',
    techniques text[] NOT NULL DEFAULT '{}',
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    soc_case_status text NOT NULL DEFAULT 'not_configured',
    soc_synced_at timestamptz,
    soc_error text
);

CREATE INDEX incidents_tenant_seen_idx ON incidents (tenant_id, last_seen_at DESC);
CREATE INDEX incidents_open_idx ON incidents (tenant_id, last_seen_at) WHERE status IN ('new', 'investigating');

CREATE TABLE incident_alerts (
    tenant_id uuid NOT NULL REFERENCES tenants (id),
    incident_id uuid NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    alert_id bigint NOT NULL REFERENCES alerts (id) ON DELETE CASCADE,
    agent_id uuid NOT NULL,
    -- Evidence keys the grouper matched on: "root:<entity>", "sha256:<hex>",
    -- "domain:<name>", "ip:<addr>", "user:<name>".
    keys text[] NOT NULL DEFAULT '{}',
    reason text NOT NULL,
    occurred_at timestamptz NOT NULL,
    added_at timestamptz NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE UNIQUE INDEX incident_alerts_alert_idx ON incident_alerts (alert_id);
CREATE INDEX incident_alerts_keys_idx ON incident_alerts USING gin (keys);
CREATE INDEX incident_alerts_tenant_time_idx ON incident_alerts (tenant_id, occurred_at DESC);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['tenant_settings', 'tenant_oidc', 'incidents', 'incident_alerts']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = tawny_current_tenant()) WITH CHECK (tenant_id = tawny_current_tenant())',
            t);
    END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_settings, tenant_oidc, incidents, incident_alerts TO tawny_app, tawny_jobs;
