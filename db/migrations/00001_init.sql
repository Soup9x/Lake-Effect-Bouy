-- +goose Up

CREATE TABLE tenants (
    id           uuid PRIMARY KEY,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    slug         text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    external_id  text NULL CHECK (length(external_id) <= 200),
    source       text NULL CHECK (source ~ '^[a-z0-9_-]{1,50}$'),
    notes        text NULL CHECK (length(notes) <= 4000),
    archived_at  timestamptz NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenants_external_pair CHECK ((external_id IS NULL) = (source IS NULL))
);
CREATE UNIQUE INDEX tenants_name_active ON tenants (lower(name)) WHERE archived_at IS NULL;
CREATE UNIQUE INDEX tenants_external ON tenants (source, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE users (
    id                  uuid PRIMARY KEY,
    email               text NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    display_name        text NOT NULL DEFAULT '' CHECK (length(display_name) <= 200),
    password_hash       text NOT NULL,
    role                text NOT NULL DEFAULT 'admin' CHECK (role IN ('admin')),
    disabled_at         timestamptz NULL,
    failed_login_count  integer NOT NULL DEFAULT 0,
    locked_until        timestamptz NULL,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email ON users (lower(email));

-- Created now so MFA can be added without schema churn; unused in Phase 1.
CREATE TABLE user_mfa_factors (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type         text NOT NULL CHECK (type IN ('totp', 'webauthn')),
    secret_enc   bytea NULL,
    credential   jsonb NULL,
    confirmed_at timestamptz NULL,
    last_used_at timestamptz NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_mfa_factors_user ON user_mfa_factors (user_id);

CREATE TABLE sessions (
    id           uuid PRIMARY KEY,
    token_hash   bytea NOT NULL UNIQUE,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_level   smallint NOT NULL CHECK (auth_level IN (1, 2)),
    mfa_required boolean NOT NULL DEFAULT false,
    csrf_token   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    ip           inet NULL,
    user_agent   text NULL,
    revoked_at   timestamptz NULL
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE enrollment_tokens (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id),
    label        text NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
    token_prefix text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    expires_at   timestamptz NOT NULL,
    max_uses     integer NULL CHECK (max_uses > 0),
    use_count    integer NOT NULL DEFAULT 0,
    revoked_at   timestamptz NULL,
    created_by   uuid NOT NULL REFERENCES users(id),
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrollment_tokens_tenant ON enrollment_tokens (tenant_id);

CREATE TABLE agents (
    id                         uuid PRIMARY KEY,
    tenant_id                  uuid NOT NULL REFERENCES tenants(id),
    enrolled_via               uuid NULL REFERENCES enrollment_tokens(id),
    credential_hash            bytea NOT NULL UNIQUE,
    credential_prev_hash       bytea NULL,
    credential_prev_expires_at timestamptz NULL,
    credential_rotated_at      timestamptz NULL,
    rotate_requested_at        timestamptz NULL,
    machine_id                 text NOT NULL,
    hostname                   text NOT NULL,
    os_family                  text NOT NULL CHECK (os_family IN ('linux', 'windows')),
    os_name                    text NOT NULL DEFAULT '',
    os_version                 text NOT NULL DEFAULT '',
    arch                       text NOT NULL DEFAULT '',
    agent_version              text NOT NULL DEFAULT '',
    clamav_engine_version      text NULL,
    signature_version          integer NULL,
    signature_date             timestamptz NULL,
    clamd_status               text NOT NULL DEFAULT 'unknown'
        CHECK (clamd_status IN ('running', 'not_responding', 'not_installed', 'unknown')),
    clamd_error                text NULL,
    last_heartbeat_at          timestamptz NULL,
    last_ip                    inet NULL,
    -- Online state as last recorded by the sweeper; used only to emit
    -- online/offline events. The UI computes online from last_heartbeat_at.
    recorded_online            boolean NOT NULL DEFAULT false,
    enrolled_at                timestamptz NOT NULL DEFAULT now(),
    revoked_at                 timestamptz NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agents_tenant_hostname ON agents (tenant_id, hostname);
CREATE INDEX agents_last_heartbeat ON agents (last_heartbeat_at);
CREATE UNIQUE INDEX agents_active_machine ON agents (tenant_id, machine_id) WHERE revoked_at IS NULL;

CREATE TABLE agent_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id    uuid NOT NULL REFERENCES agents(id),
    tenant_id   uuid NOT NULL REFERENCES tenants(id),
    type        text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}',
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_events_agent ON agent_events (agent_id, occurred_at DESC);

CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_type  text NOT NULL CHECK (actor_type IN ('user', 'system', 'agent', 'enrollment_token', 'anonymous')),
    actor_id    uuid NULL,
    actor_label text NOT NULL DEFAULT '',
    tenant_id   uuid NULL,
    action      text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_id   text NOT NULL DEFAULT '',
    outcome     text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    ip          inet NULL,
    user_agent  text NULL,
    request_id  text NULL,
    details     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_log_time ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_tenant ON audit_log (tenant_id, occurred_at DESC);
CREATE INDEX audit_log_action ON audit_log (action, occurred_at DESC);

-- audit_log is append-only. Enforced here regardless of which role connects;
-- the app role additionally only has INSERT/SELECT on it (see below).
-- +goose StatementBegin
CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();

-- Least-privilege grants for the runtime role, when deployed with separate
-- owner and app roles (see deploy/postgres-init.sh).
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cav_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, users, user_mfa_factors, sessions,
            enrollment_tokens, agents TO cav_app;
        GRANT SELECT, INSERT ON agent_events, audit_log TO cav_app;
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- Intentionally irreversible: dropping audit_log would destroy the audit trail.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION '00001_init cannot be rolled back'; END $$;
-- +goose StatementEnd
