-- goBastion - MySQL Schema
-- Use this if the app user does not have CREATE TABLE / ALTER permissions.
-- Run as root or a user with schema privileges.
--
-- Usage:
--   mysql -h <host> -u <admin> -p <dbname> < mysql.sql

-- ── users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              varchar(36) NOT NULL PRIMARY KEY,
    username        longtext NOT NULL,
    role            longtext NOT NULL,
    enabled         tinyint(1) NOT NULL DEFAULT 1,
    system_user     tinyint(1) NOT NULL DEFAULT 0,
    last_login_from longtext,
    last_login_at   datetime,
    totp_secret     longtext,
    totp_enabled    tinyint(1) NOT NULL DEFAULT 0,
    password_hash   longtext,
    backup_codes    longtext,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    UNIQUE KEY idx_username_deletedat (username(255), deleted_at),
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
    KEY idx_user_groups_user_id (user_id),
    KEY idx_user_groups_group_id (group_id),
    KEY idx_user_groups_deleted_at (deleted_at),
    KEY idx_user_group_lookup (user_id),
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
    KEY idx_ingress_keys_user_id (user_id),
    KEY idx_ingress_keys_deleted_at (deleted_at),
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
    protocol        longtext NOT NULL DEFAULT 'ssh',
    comment         longtext,
    allowed_from    longtext,
    expires_at      datetime,
    last_connection datetime,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    KEY idx_self_accesses_user_id (user_id),
    KEY idx_self_accesses_deleted_at (deleted_at),
    KEY idx_self_access_lookup (user_id),
    CONSTRAINT fk_self_accesses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── group_accesses ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS group_accesses (
    id              varchar(36) NOT NULL PRIMARY KEY,
    group_id        varchar(36) NOT NULL,
    username        longtext NOT NULL,
    server          longtext NOT NULL,
    port            bigint NOT NULL,
    protocol        longtext NOT NULL DEFAULT 'ssh',
    comment         longtext,
    allowed_from    longtext,
    expires_at      datetime,
    last_connection datetime,
    created_at      datetime,
    updated_at      datetime,
    deleted_at      datetime,
    KEY idx_group_accesses_group_id (group_id),
    KEY idx_group_accesses_deleted_at (deleted_at),
    KEY idx_group_access_lookup (group_id),
    CONSTRAINT fk_group_accesses_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
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
    KEY idx_aliases_user_id (user_id),
    KEY idx_aliases_group_id (group_id),
    KEY idx_aliases_deleted_at (deleted_at),
    CONSTRAINT fk_aliases_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_aliases_group FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE
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

-- ── Done ─────────────────────────────────────────────────────────────────────
-- Grant the goBastion app user minimal privileges:
--   GRANT SELECT, INSERT, UPDATE, DELETE ON gobastion.* TO 'gobastion'@'%';
--   FLUSH PRIVILEGES;
