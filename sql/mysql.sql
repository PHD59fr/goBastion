-- goBastion - MySQL Schema
-- Use this if the app user does not have CREATE TABLE / ALTER permissions.
-- Run as root or a user with schema privileges.
--
-- Usage:
--   mysql -h <host> -u <admin> -p <dbname> < mysql.sql

-- ── bastion_instances ───────────────────────────────────────────────────────
-- Stores per-instance configuration (DB is the source of truth for config).
-- The Config column holds a JSON-encoded copy of the full configuration
-- (everything except bootstrap DB connection params).
CREATE TABLE IF NOT EXISTS bastion_instances (
    instance_id varchar(191) NOT NULL PRIMARY KEY,
    role        varchar(32) NOT NULL DEFAULT 'master', -- 'master' or 'slave'
    config      longtext,                 -- JSON-encoded config
    created_at  datetime,
    updated_at  datetime
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── active_sessions ──────────────────────────────────────────────────────────
-- Tracks authenticated sessions currently running on this bastion instance.
-- Used for instance-wide max_concurrent_sessions enforcement.
CREATE TABLE IF NOT EXISTS active_sessions (
    session_id  varchar(36) NOT NULL PRIMARY KEY,
    instance_id varchar(191) NOT NULL,
    username    longtext NOT NULL,
    p_id        bigint NOT NULL,
    kind        longtext NOT NULL,
    created_at  datetime,
    updated_at  datetime,
    KEY idx_active_sessions_instance_id (instance_id),
    KEY idx_active_sessions_username (username(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              varchar(36) NOT NULL PRIMARY KEY,
    username        longtext NOT NULL,
    role            longtext NOT NULL,
    enabled         tinyint(1) NOT NULL DEFAULT 1,
    system_user     tinyint(1) NOT NULL DEFAULT 0,
    osh_only        tinyint(1) NOT NULL DEFAULT 0,
    super_owner     tinyint(1) NOT NULL DEFAULT 0,
    last_login_from longtext,
    last_login_at   datetime,
    totp_secret     longtext,
    totp_enabled    tinyint(1) NOT NULL DEFAULT 0,
    password_hash   longtext,
    backup_codes    longtext,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    active_username_hash binary(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN UNHEX(SHA2(LOWER(username), 256)) ELSE NULL END) VIRTUAL,
    KEY idx_username_deletedat (username(255), deleted_at),
    UNIQUE KEY uq_active_users_username (active_username_hash),
    KEY idx_users_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── groups ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `groups` (
    id           varchar(36) NOT NULL PRIMARY KEY,
    name         longtext NOT NULL,
    mfa_required tinyint(1) NOT NULL DEFAULT 0,
    created_at   datetime,
    updated_at   datetime,
    deleted_at   datetime,
    UNIQUE KEY idx_groupname_deletedat (name(255), deleted_at),
    KEY idx_groups_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── user_groups ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_groups (
    id         varchar(36) NOT NULL PRIMARY KEY,
    user_id    varchar(36) NOT NULL,
    group_id   varchar(36) NOT NULL,
    role       longtext NOT NULL,
    created_at datetime,
    updated_at datetime,
    deleted_at datetime,
    active_membership_hash binary(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', group_id), 256)) ELSE NULL END) VIRTUAL,
    KEY idx_user_groups_user_id (user_id),
    KEY idx_user_groups_group_id (group_id),
    KEY idx_user_groups_deleted_at (deleted_at),
    KEY idx_user_group_lookup (user_id, group_id),
    UNIQUE KEY uq_active_user_groups_membership (active_membership_hash),
    CONSTRAINT fk_user_groups_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_groups_group FOREIGN KEY (group_id) REFERENCES `groups`(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── ingress_keys ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ingress_keys (
    id           varchar(36) NOT NULL PRIMARY KEY,
    user_id      varchar(36) NOT NULL,
    `key`        longtext NOT NULL,
    type         longtext NOT NULL,
    size         bigint NOT NULL,
    fingerprint  longtext NOT NULL,
    comment      longtext,
    expires_at   datetime,
    piv_attested tinyint(1) NOT NULL DEFAULT 0,
    created_at   datetime,
    updated_at   datetime,
    deleted_at   datetime,
    active_fingerprint_hash binary(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', fingerprint), 256)) ELSE NULL END) VIRTUAL,
    KEY idx_ingress_keys_user_id (user_id),
    KEY idx_ingress_keys_deleted_at (deleted_at),
    UNIQUE KEY uq_active_ingress_keys_fingerprint (active_fingerprint_hash),
    CONSTRAINT fk_ingress_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── self_egress_keys ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS self_egress_keys (
    id          varchar(36) NOT NULL PRIMARY KEY,
    user_id     varchar(36) NOT NULL,
    pub_key     longtext NOT NULL,
    priv_key    longtext NOT NULL,
    type        longtext NOT NULL,
    size        bigint NOT NULL,
    fingerprint longtext NOT NULL,
    created_at  datetime,
    updated_at  datetime,
    deleted_at  datetime,
    KEY idx_self_egress_keys_user_id (user_id),
    KEY idx_self_egress_keys_deleted_at (deleted_at),
    CONSTRAINT fk_self_egress_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── group_egress_keys ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS group_egress_keys (
    id          varchar(36) NOT NULL PRIMARY KEY,
    group_id    varchar(36) NOT NULL,
    pub_key     longtext NOT NULL,
    priv_key    longtext NOT NULL,
    type        longtext NOT NULL,
    size        bigint NOT NULL,
    fingerprint longtext NOT NULL,
    created_at  datetime,
    updated_at  datetime,
    deleted_at  datetime,
    KEY idx_group_egress_keys_group_id (group_id),
    KEY idx_group_egress_keys_deleted_at (deleted_at),
    CONSTRAINT fk_group_egress_keys_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── self_accesses ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS self_accesses (
    id              varchar(36) NOT NULL PRIMARY KEY,
    user_id         varchar(36) NOT NULL,
    username        longtext NOT NULL,
    server          longtext NOT NULL,
    port            bigint NOT NULL,
    protocol        varchar(32) NOT NULL DEFAULT 'ssh',
    comment         longtext,
    allowed_from    longtext,
    expires_at      datetime,
    last_connection datetime,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    KEY idx_self_accesses_user_id (user_id),
    KEY idx_self_accesses_deleted_at (deleted_at),
    KEY idx_self_access_lookup (user_id, server(191), port, username(191), protocol(32)),
    CONSTRAINT fk_self_accesses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── group_accesses ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS group_accesses (
    id              varchar(36) NOT NULL PRIMARY KEY,
    group_id        varchar(36) NOT NULL,
    username        longtext NOT NULL,
    server          longtext NOT NULL,
    port            bigint NOT NULL,
    protocol        varchar(32) NOT NULL DEFAULT 'ssh',
    comment         longtext,
    allowed_from    longtext,
    expires_at      datetime,
    last_connection datetime,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    KEY idx_group_accesses_group_id (group_id),
    KEY idx_group_accesses_deleted_at (deleted_at),
    KEY idx_group_access_lookup (group_id, server(191), port, username(191), protocol(32)),
    CONSTRAINT fk_group_accesses_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── group_guest_accesses ─────────────────────────────────────────────────────
-- Granular per-user, per-server guest access grants.
-- A guest-role user can only connect to servers listed in their grants.
CREATE TABLE IF NOT EXISTS group_guest_accesses (
    id            varchar(36) NOT NULL PRIMARY KEY,
    group_id      varchar(36) NOT NULL,
    user_id       varchar(36) NOT NULL,
    username      longtext NOT NULL,
    server        longtext NOT NULL,
    port          bigint NOT NULL,
    protocol      varchar(32) NOT NULL DEFAULT 'ssh',
    comment       longtext,
    allowed_from  longtext,
    expires_at    datetime,
    created_at    datetime,
    updated_at    datetime,
    deleted_at    datetime,
    KEY idx_group_guest_accesses_group_id (group_id),
    KEY idx_group_guest_accesses_user_id (user_id),
    KEY idx_group_guest_accesses_deleted_at (deleted_at),
    CONSTRAINT fk_group_guest_accesses_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
    CONSTRAINT fk_group_guest_accesses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── aliases ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aliases (
    id           varchar(36) NOT NULL PRIMARY KEY,
    resolve_from longtext NOT NULL,
    host         longtext NOT NULL,
    user_id      varchar(36),
    group_id     varchar(36),
    created_at   datetime,
    updated_at   datetime,
    deleted_at   datetime,
    active_user_alias_hash binary(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND user_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL,
    active_group_alias_hash binary(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND group_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(group_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL,
    KEY idx_aliases_user_id (user_id),
    KEY idx_aliases_group_id (group_id),
    KEY idx_aliases_deleted_at (deleted_at),
    UNIQUE KEY uq_active_aliases_user (active_user_alias_hash),
    UNIQUE KEY uq_active_aliases_group (active_group_alias_hash),
    CONSTRAINT fk_aliases_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_aliases_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── self_db_accesses ─────────────────────────────────────────────────────────
-- Supported protocols in the bundled container image: mysql, postgres, redis.
-- Passwords are encrypted when EGRESS_ENC_KEY is configured; otherwise they are stored as plaintext.
CREATE TABLE IF NOT EXISTS self_db_accesses (
    id              varchar(36) NOT NULL PRIMARY KEY,
    user_id         varchar(36) NOT NULL,
    host            longtext NOT NULL,
    port            bigint NOT NULL,
    protocol        longtext NOT NULL,
    username        longtext NOT NULL,
    password        longtext,
    `database`      longtext,
    comment         longtext,
    allowed_from    longtext,
    expires_at      datetime,
    last_connection datetime,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    KEY idx_self_db_accesses_user_id (user_id),
    KEY idx_self_db_accesses_deleted_at (deleted_at),
    KEY idx_self_db_access_lookup (user_id, host(191), port, username(191), protocol(32)),
    CONSTRAINT fk_self_db_accesses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── group_db_accesses ────────────────────────────────────────────────────────
-- Supported protocols in the bundled container image: mysql, postgres, redis.
-- Passwords are encrypted when EGRESS_ENC_KEY is configured; otherwise they are stored as plaintext.
CREATE TABLE IF NOT EXISTS group_db_accesses (
    id              varchar(36) NOT NULL PRIMARY KEY,
    group_id        varchar(36) NOT NULL,
    host            longtext NOT NULL,
    port            bigint NOT NULL,
    protocol        longtext NOT NULL,
    username        longtext NOT NULL,
    password        longtext,
    `database`      longtext,
    comment         longtext,
    allowed_from    longtext,
    expires_at      datetime,
    last_connection datetime,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    KEY idx_group_db_accesses_group_id (group_id),
    KEY idx_group_db_accesses_deleted_at (deleted_at),
    KEY idx_group_db_access_lookup (group_id, host(191), port, username(191), protocol(32)),
    CONSTRAINT fk_group_db_accesses_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── group_guest_db_accesses ──────────────────────────────────────────────────
-- Granular per-user, per-database guest access grants.
-- A guest-role user can only connect to database targets listed in their grants.
-- Supported protocols in the bundled container image: mysql, postgres, redis.
-- Passwords are encrypted when EGRESS_ENC_KEY is configured; otherwise they are stored as plaintext.
CREATE TABLE IF NOT EXISTS group_guest_db_accesses (
    id           varchar(36) NOT NULL PRIMARY KEY,
    group_id     varchar(36) NOT NULL,
    user_id      varchar(36) NOT NULL,
    host         longtext NOT NULL,
    port         bigint NOT NULL,
    protocol     longtext NOT NULL,
    username     longtext NOT NULL,
    password     longtext,
    `database`   longtext,
    comment      longtext,
    allowed_from longtext,
    expires_at   datetime,
    created_at   datetime,
    updated_at   datetime,
    deleted_at   datetime,
    KEY idx_group_guest_db_accesses_group_id (group_id),
    KEY idx_group_guest_db_accesses_user_id (user_id),
    KEY idx_group_guest_db_accesses_deleted_at (deleted_at),
    CONSTRAINT fk_group_guest_db_accesses_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
    CONSTRAINT fk_group_guest_db_accesses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── database_aliases ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS database_aliases (
    id           varchar(36) NOT NULL PRIMARY KEY,
    resolve_from longtext NOT NULL,
    host         longtext NOT NULL,
    port         bigint NOT NULL,
    protocol     longtext NOT NULL,
    user_id      varchar(36),
    group_id     varchar(36),
    created_at   datetime,
    updated_at   datetime,
    deleted_at   datetime,
    active_user_alias_hash binary(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND user_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL,
    active_group_alias_hash binary(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND group_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(group_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL,
    KEY idx_database_aliases_user_id (user_id),
    KEY idx_database_aliases_group_id (group_id),
    KEY idx_database_aliases_deleted_at (deleted_at),
    UNIQUE KEY uq_active_database_aliases_user (active_user_alias_hash),
    UNIQUE KEY uq_active_database_aliases_group (active_group_alias_hash),
    CONSTRAINT fk_database_aliases_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_database_aliases_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── ssh_host_keys ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ssh_host_keys (
    type        varchar(191) NOT NULL PRIMARY KEY,
    private_key longblob,
    public_key  longblob
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── known_hosts_entries ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS known_hosts_entries (
    id         varchar(36) NOT NULL PRIMARY KEY,
    user_id    varchar(36) NOT NULL,
    entry      longtext NOT NULL,
    created_at datetime,
    updated_at datetime,
    deleted_at datetime,
    KEY idx_known_hosts_entries_user_id (user_id),
    KEY idx_known_hosts_entries_deleted_at (deleted_at),
    CONSTRAINT fk_known_hosts_entries_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── piv_trust_anchors ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS piv_trust_anchors (
    id          varchar(36) NOT NULL PRIMARY KEY,
    name        longtext NOT NULL,
    cert_pem    longtext NOT NULL,
    added_by_id varchar(36) NOT NULL,
    created_at  datetime,
    updated_at  datetime,
    deleted_at  datetime,
    UNIQUE KEY idx_piv_trust_anchors_name (name(255)),
    KEY idx_piv_trust_anchors_deleted_at (deleted_at),
    CONSTRAINT fk_piv_trust_anchors_user FOREIGN KEY (added_by_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── realms ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS realms (
    id              varchar(36) NOT NULL PRIMARY KEY,
    name            longtext NOT NULL,
    bastion_host    longtext NOT NULL,
    bastion_port    bigint NOT NULL DEFAULT 22,
    allowed_from    longtext NOT NULL,
    public_key      longtext NOT NULL,
    enabled         tinyint(1) NOT NULL DEFAULT 1,
    created_by_id   varchar(36) NOT NULL,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    UNIQUE KEY idx_realms_name (name(255)),
    KEY idx_realms_deleted_at (deleted_at),
    CONSTRAINT fk_realms_created_by FOREIGN KEY (created_by_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── restricted_command_grants ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS restricted_command_grants (
    id            varchar(36) NOT NULL PRIMARY KEY,
    user_id       varchar(36) NOT NULL,
    command       longtext NOT NULL,
    granted_by_id varchar(36) NOT NULL,
    created_at    datetime,
    updated_at    datetime,
    deleted_at    datetime,
    UNIQUE KEY idx_user_command_grant (user_id, command(255), deleted_at),
    KEY idx_restricted_command_grants_deleted_at (deleted_at),
    CONSTRAINT fk_restricted_command_grants_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_restricted_command_grants_granted_by FOREIGN KEY (granted_by_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Preflight and upgrade active-row business identities for existing databases.
-- This intentionally aborts instead of deleting or merging duplicate rows.
DROP PROCEDURE IF EXISTS gobastion_add_active_identity_indexes;
DELIMITER //
CREATE PROCEDURE gobastion_add_active_identity_indexes()
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE deleted_at IS NULL GROUP BY LOWER(username) HAVING COUNT(*) > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'duplicate active usernames exist; resolve manually (no data deleted)';
    END IF;
    IF EXISTS (SELECT 1 FROM user_groups WHERE deleted_at IS NULL GROUP BY user_id, group_id HAVING COUNT(*) > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'duplicate active memberships exist; resolve manually (no data deleted)';
    END IF;
    IF EXISTS (SELECT 1 FROM ingress_keys WHERE deleted_at IS NULL GROUP BY user_id, fingerprint HAVING COUNT(*) > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'duplicate active ingress keys exist; resolve manually (no data deleted)';
    END IF;
    IF EXISTS (SELECT 1 FROM aliases WHERE deleted_at IS NULL AND user_id IS NOT NULL GROUP BY user_id, LOWER(resolve_from) HAVING COUNT(*) > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'duplicate active personal aliases exist; resolve manually (no data deleted)';
    END IF;
    IF EXISTS (SELECT 1 FROM aliases WHERE deleted_at IS NULL AND group_id IS NOT NULL GROUP BY group_id, LOWER(resolve_from) HAVING COUNT(*) > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'duplicate active group aliases exist; resolve manually (no data deleted)';
    END IF;
    IF EXISTS (SELECT 1 FROM database_aliases WHERE deleted_at IS NULL AND user_id IS NOT NULL GROUP BY user_id, LOWER(resolve_from) HAVING COUNT(*) > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'duplicate active personal DB aliases exist; resolve manually (no data deleted)';
    END IF;
    IF EXISTS (SELECT 1 FROM database_aliases WHERE deleted_at IS NULL AND group_id IS NOT NULL GROUP BY group_id, LOWER(resolve_from) HAVING COUNT(*) > 1) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'duplicate active group DB aliases exist; resolve manually (no data deleted)';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'active_username_hash') THEN
        ALTER TABLE users ADD COLUMN active_username_hash BINARY(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN UNHEX(SHA2(LOWER(username), 256)) ELSE NULL END) VIRTUAL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'users' AND index_name = 'uq_active_users_username') THEN
        CREATE UNIQUE INDEX uq_active_users_username ON users (active_username_hash);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'user_groups' AND column_name = 'active_membership_hash') THEN
        ALTER TABLE user_groups ADD COLUMN active_membership_hash BINARY(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', group_id), 256)) ELSE NULL END) VIRTUAL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'user_groups' AND index_name = 'uq_active_user_groups_membership') THEN
        CREATE UNIQUE INDEX uq_active_user_groups_membership ON user_groups (active_membership_hash);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'ingress_keys' AND column_name = 'active_fingerprint_hash') THEN
        ALTER TABLE ingress_keys ADD COLUMN active_fingerprint_hash BINARY(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', fingerprint), 256)) ELSE NULL END) VIRTUAL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'ingress_keys' AND index_name = 'uq_active_ingress_keys_fingerprint') THEN
        CREATE UNIQUE INDEX uq_active_ingress_keys_fingerprint ON ingress_keys (active_fingerprint_hash);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'aliases' AND column_name = 'active_user_alias_hash') THEN
        ALTER TABLE aliases ADD COLUMN active_user_alias_hash BINARY(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND user_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'aliases' AND column_name = 'active_group_alias_hash') THEN
        ALTER TABLE aliases ADD COLUMN active_group_alias_hash BINARY(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND group_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(group_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'aliases' AND index_name = 'uq_active_aliases_user') THEN
        CREATE UNIQUE INDEX uq_active_aliases_user ON aliases (active_user_alias_hash);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'aliases' AND index_name = 'uq_active_aliases_group') THEN
        CREATE UNIQUE INDEX uq_active_aliases_group ON aliases (active_group_alias_hash);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'database_aliases' AND column_name = 'active_user_alias_hash') THEN
        ALTER TABLE database_aliases ADD COLUMN active_user_alias_hash BINARY(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND user_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(user_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'database_aliases' AND column_name = 'active_group_alias_hash') THEN
        ALTER TABLE database_aliases ADD COLUMN active_group_alias_hash BINARY(32) GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL AND group_id IS NOT NULL THEN UNHEX(SHA2(CONCAT(group_id, ':', LOWER(resolve_from)), 256)) ELSE NULL END) VIRTUAL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'database_aliases' AND index_name = 'uq_active_database_aliases_user') THEN
        CREATE UNIQUE INDEX uq_active_database_aliases_user ON database_aliases (active_user_alias_hash);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'database_aliases' AND index_name = 'uq_active_database_aliases_group') THEN
        CREATE UNIQUE INDEX uq_active_database_aliases_group ON database_aliases (active_group_alias_hash);
    END IF;
END//
DELIMITER ;
CALL gobastion_add_active_identity_indexes();
DROP PROCEDURE gobastion_add_active_identity_indexes;

-- ── Done ─────────────────────────────────────────────────────────────────────
-- Grant the goBastion app user minimal privileges:
--   GRANT SELECT, INSERT, UPDATE, DELETE ON gobastion.* TO 'gobastion'@'%';
--   FLUSH PRIVILEGES;
