-- goBastion - PostgreSQL Schema
-- Use this if the app user does not have CREATE TABLE / ALTER permissions.
-- Run as a superuser or a user with schema privileges.
--
-- Usage:
--   psql -h <host> -U <admin> -d <dbname> -f postgres.sql

-- ── Extensions ───────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              uuid PRIMARY KEY,
    username        text NOT NULL,
    role            text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    system_user     boolean NOT NULL DEFAULT false,
    last_login_from text,
    last_login_at   timestamptz,
    totp_secret     text,
    totp_enabled    boolean NOT NULL DEFAULT false,
    password_hash   text,
    backup_codes    text,
    created_at      timestamptz,
    updated_at      timestamptz,
    deleted_at      timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_username_deletedat ON users (username, deleted_at);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users (deleted_at);

-- ── groups ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS groups (
    id           uuid PRIMARY KEY,
    name         text NOT NULL,
    mfa_required boolean NOT NULL DEFAULT false,
    created_at   timestamptz,
    updated_at   timestamptz,
    deleted_at   timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_groupname_deletedat ON groups (name, deleted_at);
CREATE INDEX IF NOT EXISTS idx_groups_deleted_at ON groups (deleted_at);

-- ── user_groups ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_groups (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id   uuid NOT NULL REFERENCES groups(id),
    role       text NOT NULL,
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups (user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups (group_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_deleted_at ON user_groups (deleted_at);
CREATE INDEX IF NOT EXISTS idx_user_group_lookup ON user_groups (user_id, group_id) WHERE deleted_at IS NULL;

-- ── ingress_keys ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingress_keys (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key          text NOT NULL,
    type         text NOT NULL,
    size         integer NOT NULL,
    fingerprint  text NOT NULL,
    comment      text,
    expires_at   timestamptz,
    piv_attested boolean NOT NULL DEFAULT false,
    created_at   timestamptz,
    updated_at   timestamptz,
    deleted_at   timestamptz
);
CREATE INDEX IF NOT EXISTS idx_ingress_keys_user_id ON ingress_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_ingress_keys_deleted_at ON ingress_keys (deleted_at);

-- ── self_egress_keys ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS self_egress_keys (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pub_key     text NOT NULL,
    priv_key    text NOT NULL,
    type        text NOT NULL,
    size        integer NOT NULL,
    fingerprint text NOT NULL,
    created_at  timestamptz,
    updated_at  timestamptz,
    deleted_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_self_egress_keys_user_id ON self_egress_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_self_egress_keys_deleted_at ON self_egress_keys (deleted_at);

-- ── group_egress_keys ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS group_egress_keys (
    id          uuid PRIMARY KEY,
    group_id    uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    pub_key     text NOT NULL,
    priv_key    text NOT NULL,
    type        text NOT NULL,
    size        integer NOT NULL,
    fingerprint text NOT NULL,
    created_at  timestamptz,
    updated_at  timestamptz,
    deleted_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_group_egress_keys_group_id ON group_egress_keys (group_id);
CREATE INDEX IF NOT EXISTS idx_group_egress_keys_deleted_at ON group_egress_keys (deleted_at);

-- ── self_accesses ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS self_accesses (
    id             uuid PRIMARY KEY,
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username       text NOT NULL,
    server         text NOT NULL,
    port           bigint NOT NULL,
    protocol       text NOT NULL DEFAULT 'ssh',
    comment        text,
    allowed_from   text,
    expires_at     timestamptz,
    last_connection timestamptz,
    created_at     timestamptz,
    updated_at     timestamptz,
    deleted_at     timestamptz
);
CREATE INDEX IF NOT EXISTS idx_self_accesses_user_id ON self_accesses (user_id);
CREATE INDEX IF NOT EXISTS idx_self_accesses_deleted_at ON self_accesses (deleted_at);
CREATE INDEX IF NOT EXISTS idx_self_access_lookup ON self_accesses (user_id, server, port, username, protocol) WHERE deleted_at IS NULL;

-- ── group_accesses ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS group_accesses (
    id              uuid PRIMARY KEY,
    group_id        uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    username        text NOT NULL,
    server          text NOT NULL,
    port            bigint NOT NULL,
    protocol        text NOT NULL DEFAULT 'ssh',
    comment         text,
    allowed_from    text,
    expires_at      timestamptz,
    last_connection timestamptz,
    created_at      timestamptz,
    updated_at      timestamptz,
    deleted_at      timestamptz
);
CREATE INDEX IF NOT EXISTS idx_group_accesses_group_id ON group_accesses (group_id);
CREATE INDEX IF NOT EXISTS idx_group_accesses_deleted_at ON group_accesses (deleted_at);
CREATE INDEX IF NOT EXISTS idx_group_access_lookup ON group_accesses (group_id, server, port, username, protocol) WHERE deleted_at IS NULL;

-- ── aliases ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aliases (
    id          uuid PRIMARY KEY,
    resolve_from text NOT NULL,
    host        text NOT NULL,
    user_id     uuid REFERENCES users(id) ON DELETE CASCADE,
    group_id    uuid REFERENCES groups(id) ON DELETE CASCADE,
    created_at  timestamptz,
    updated_at  timestamptz,
    deleted_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_aliases_user_id ON aliases (user_id);
CREATE INDEX IF NOT EXISTS idx_aliases_group_id ON aliases (group_id);
CREATE INDEX IF NOT EXISTS idx_aliases_deleted_at ON aliases (deleted_at);

-- ── ssh_host_keys ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ssh_host_keys (
    type       text PRIMARY KEY,
    private_key bytea,
    public_key  bytea
);

-- ── known_hosts_entries ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS known_hosts_entries (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    entry      text NOT NULL,
    created_at timestamptz,
    updated_at timestamptz,
    deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_known_hosts_entries_user_id ON known_hosts_entries (user_id);
CREATE INDEX IF NOT EXISTS idx_known_hosts_entries_deleted_at ON known_hosts_entries (deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS unique_user_entry ON known_hosts_entries (user_id, entry) WHERE deleted_at IS NULL;

-- ── piv_trust_anchors ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS piv_trust_anchors (
    id          uuid PRIMARY KEY,
    name        text NOT NULL,
    cert_pem    text NOT NULL,
    added_by_id uuid NOT NULL REFERENCES users(id),
    created_at  timestamptz,
    updated_at  timestamptz,
    deleted_at  timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_piv_trust_anchors_name ON piv_trust_anchors (name);
CREATE INDEX IF NOT EXISTS idx_piv_trust_anchors_deleted_at ON piv_trust_anchors (deleted_at);

-- ── PRAGMA equivalents (PostgreSQL) ──────────────────────────────────────────
-- WAL is the default for PostgreSQL, no equivalent needed.
-- Connection pooling should be configured in the application or via PgBouncer.

-- ── Done ─────────────────────────────────────────────────────────────────────
-- Grant the goBastion app user SELECT/INSERT/UPDATE/DELETE on all tables:
--   GRANT USAGE ON SCHEMA public TO gobastion;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gobastion;
--   ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO gobastion;
