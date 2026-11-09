# Architecture overview

goBastion is a Go SSH bastion. Its control-plane database is the system of record for accounts, roles, keys, access assignments, aliases, policy, MFA metadata, active sessions, instance configuration, and realm relay metadata. Supported database drivers are SQLite, MySQL, and PostgreSQL. Root startup performs schema migration; ForceCommand sessions skip migrations.

## Runtime components

- **SSH entrypoint and commands:** `Dockerfile` and `entrypoint.sh` configure the container and sshd. SSH public-key authentication enters the constrained ForceCommand command registry. Session policy is refreshed before command dispatch; command failures are returned through the process status while deferred cleanup runs.
- **Authorization and administration:** `internal/models` owns persistent models and access policy. `internal/session` handles admission, MFA flows, policy refresh, session lifecycle, and audit logging.
- **Outbound SSH:** `internal/utils/sshConnector` resolves authorized access and connects to targets using configured host keys and egress identities. Groups, aliases, guest grants, and realms contribute to access resolution and routing.
- **Database clients:** `internal/session/db_supervisor.go`, `internal/dbsandbox`, and `cmd/dbworker` implement the privileged broker path. The supervisor selects fixed supported clients and launches them in NsJail with a restricted filesystem and resource/security limits. Credentials pass through the broker rather than ordinary client command-line arguments.
- **Persistence and secrets:** `internal/db` owns database connections, schema, and encrypted logical import/export. `internal/utils/cryptokey` encrypts persisted application secrets. `internal/secretstore` inventories seven persisted secret columns, including soft-deleted records; `cmd/secret-migrate` provides explicit offline conversion, rotation, backup, and restore operations.
- **Recordings:** SSH and database capture paths spool and publish compressed recordings. `internal/recording` handles publication and interrupted-work recovery. `cmd/recording-admin` can seal, verify, decrypt, and migrate metadata for imported/archive recordings. Live capture files remain plaintext; the archive format is not integrated into automatic capture publication.
- **Observability:** `cmd/observability` serves authenticated loopback metrics backed by `internal/observability`. `internal/telemetry` provides optional bounded OpenTelemetry tracing. These facilities do not constitute SSH readiness, admission control, or an audit-delivery guarantee.

## Security and storage boundaries

Nonempty persisted-secret operations require canonical base64 AES-256 `EGRESS_ENC_KEY`. New ciphertext uses authenticated `gob:v2` envelopes that bind format version and key ID. `EGRESS_ENC_KEY_ID` selects the active ID; historical AES-128/192/256 keys may be configured for authenticated decryption. Coordinate active-key changes across all v2-capable instances and retain historical keys until offline migration is verified. Old binaries cannot read v2 ciphertext, so mixed-version rollback after v2 writes is unsupported.

Field encryption does not encrypt the database file, WAL, physical backups/snapshots, recordings, or storage media. Logical DB export/import uses the separate `DB_EXPORT_KEY`; it is not a physical backup. The application and ForceCommand sessions access control-plane data and configured egress keys directly, including with server-backed databases. The local SQLite DB/WAL also remains exposed to local bastion identities with filesystem access. These are control-plane confidentiality and integrity boundaries.

Production recording storage uses a root:gobastion archive root (0751), account:gobastion-auditors directories (02750), and account:gobastion-auditors files (0640). ACLs that cannot be represented by the expected owner/mode checks are refused. Existing legacy archive layouts require the explicit offline `recording-admin permissions` migration; startup does not recursively repair trees. Live recordings remain plaintext and require separate storage and backup controls.

Privileged SSH-file publication uses descriptor-relative traversal and checks ownership and permissions of every path component. User-owned `authorized_keys` remains the source read by sshd, so periodic reconciliation does not provide immediate root-enforced ingress-key revocation. Account retirement reserves the Unix name and UID; it does not perform native account deletion.

## Availability and consistency limits

The node-local reconciliation lock serializes participating host-state reconciliation on one node. It is not distributed admission control or atomic database/filesystem revocation. Active session records and concurrency limits are instance-scoped; local PID checks cannot establish remote process liveness. Shutdown does not establish a drain state or wait for sessions.

PostgreSQL root startup migrations use a session advisory lock among participating goBastion versions. SQLite migration behavior is standalone and intended for one local instance; shared multi-host SQLite is not qualified. MySQL migrations do not use this distributed lock. These migration controls do not provide application high availability, cluster-wide revocation, failover readiness, or zero-downtime upgrades.

## Code map

| Concern | Location |
|---|---|
| Entrypoint and image/runtime | `entrypoint.sh`, `Dockerfile`, `scripts/sudo/` |
| Database and schema | `internal/db/`, `sql/` |
| Models and access policy | `internal/models/` |
| SSH dispatch and session | `internal/commands/`, `internal/session/` |
| Database-client isolation | `internal/dbsandbox/`, `cmd/dbworker/`, `profiles/` |
| Secret encryption and logical export | `internal/utils/cryptokey/`, `internal/db/export.go` |
| Recording lifecycle and archive CLI | `internal/recording/`, `cmd/recording-admin/` |
| Metrics and tracing | `internal/observability/`, `internal/telemetry/`, `cmd/observability/` |

See [security analysis](../security/SECURITY_AUDIT.md).
