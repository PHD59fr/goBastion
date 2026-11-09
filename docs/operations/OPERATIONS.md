# Operations guide

Operational behavior and procedures for configuring, upgrading, and recovering a goBastion deployment. Rehearse database and filesystem changes against a protected copy of deployment data before applying them.

## Runtime and configuration

- `Dockerfile` and `entrypoint.sh` define the image and process startup. Root startup performs schema migrations; ForceCommand sessions skip migrations. On shutdown, the entrypoint stops accepting new SSH connections, then waits up to `DRAIN_TIMEOUT_SECONDS` (default `30`) for active managed user sessions to exit before stopping background services.
- `DB_DRIVER` and `DB_DSN` select SQLite, MySQL, or PostgreSQL. Protect DSNs and generated configuration files as credentials. SQLite is intended for a single local instance; shared multi-host SQLite is not qualified.
- Nonempty persisted-secret operations require canonical base64 AES-256 `EGRESS_ENC_KEY`. `EGRESS_ENC_KEY_ID` selects the active key ID (default `default`). `EGRESS_ENC_KEYS` is a JSON map of historical IDs to canonical base64 AES-128/192/256 decryption keys. File variants `EGRESS_ENC_KEY_FILE` and `EGRESS_ENC_KEYS_FILE` are available. Key settings load at process start; coordinate changes and restart all instances.
- Persisted field encryption covers application secrets such as egress private keys, DB access passwords, SSH host private keys, and TOTP secrets. It does not encrypt database files/WAL, physical backups, recordings, or storage media. `DB_EXPORT_KEY` separately protects logical export/import data.
- Optional AppArmor/seccomp behavior depends on host and container runtime support. See `profiles/Readme.md` and the deployment instructions in the repository README.

## Secret migration and key rotation

Use `secret-migrate` for explicit plaintext conversion, historical-key migration, rotation, and encrypted logical backup/restore. Drain and stop every instance before apply. The active-session count check is point-in-time and does not block new admissions. Do not use `docker exec`; run the image's root-only maintenance binary with the normal entrypoint overridden.

For SQLite, mount the exact persistent volume used by the stopped service. For server databases, supply the protected driver/DSN and database network instead. Keep active and historical key files read-only and separate from the database. Use a separate protected environment file for `DB_EXPORT_KEY`; keep all maintenance environment files mode `0600`.

```sh
IMAGE=gobastion:latest
MAINT_ENV=/secure/path/gobastion-maintenance.env
DATA_VOLUME=gobastion-data
SECRET_DIR=/secure/path/gobastion-secrets
BACKUP_DIR=/secure/path/gobastion-migration-backups

# Inspect the stopped database without authorizing plaintext conversion.
docker run --rm --user 0:0 --env-file "$MAINT_ENV" \
  --mount "type=volume,src=$DATA_VOLUME,dst=/var/lib/goBastion" \
  --mount "type=bind,src=$SECRET_DIR/active-key,dst=/run/secrets/active-key,readonly" \
  --mount "type=bind,src=$SECRET_DIR/historical-keyring.json,dst=/run/secrets/keyring.json,readonly" \
  --entrypoint /app/secret-migrate "$IMAGE"

# Apply an explicitly authorized plaintext conversion with encrypted backup.
EXPORT_ENV=/secure/path/gobastion-export.env
# EXPORT_ENV contains DB_EXPORT_KEY and is mode 0600.
docker run --rm --user 0:0 --env-file "$MAINT_ENV" --env-file "$EXPORT_ENV" \
  --mount "type=volume,src=$DATA_VOLUME,dst=/var/lib/goBastion" \
  --mount "type=bind,src=$SECRET_DIR/active-key,dst=/run/secrets/active-key,readonly" \
  --mount "type=bind,src=$SECRET_DIR/historical-keyring.json,dst=/run/secrets/keyring.json,readonly" \
  --mount "type=bind,src=$BACKUP_DIR,dst=/migration" \
  --entrypoint /app/secret-migrate "$IMAGE" --apply --allow-plaintext \
  --backup /migration/migration-backup.gob
```

For external databases, omit the SQLite volume mount and add the database Docker network. Restore with `--restore-backup` only into an empty target database, using the same export key and the target's DB configuration. The backup path must not already exist; backup files are created exclusively with mode `0600`. A killed backup operation can leave a partial file that must be handled explicitly.

A coordinated v2 key rotation follows this order:

1. Upgrade all instances to a v2-capable release and stop old binaries before any v2 writes. Old releases cannot read v2 ciphertext.
2. Preload the new key under its future ID in the historical keyring on every instance while retaining the current active key. Restart and confirm the configured readers have both keys.
3. Coordinate a restart with the new key and matching `EGRESS_ENC_KEY_ID` active on every instance. Keep the old key in the historical keyring.
4. Drain and stop all instances; run offline dry-run and apply with an encrypted backup. Migration covers all seven inventory columns, including soft-deleted records.
5. Repeat dry-run and confirm there are no changes. Retain historical keys until no live record or retained backup depends on them; keep the protected backup and its recovery keys.

Mixed active keys and rolling rollback to a pre-v2 binary after v2 writes are unsupported. Historical key conversion must preserve the exact bytes the old decoder used; validate legacy keys against a protected backup instead of guessing. Plaintext authorization can be ambiguous for legacy values that resemble ciphertext, so classify legacy data before using `--allow-plaintext`.

## Backups and recovery

Back up the control-plane database using the selected engine's consistent backup procedure. A SQLite backup must include a consistent database snapshot and required WAL/sidecar state. Back up recordings and other persistent state under the deployment's retention policy. Store encryption and export keys separately from databases and backups. Restore into an isolated environment first and validate schema, key availability, login, and representative access flows before cutover. Loss of a required key can make encrypted fields or exports unrecoverable. Field encryption does not erase old plaintext pages or WAL content.

## Reconciliation and SSH files

Root startup, periodic sync, manual root sync, and the privileged single-user helper use the node-local `/run/gobastion/reconcile.lock`. It has a 30-second acquisition timeout; failure prevents that reconciliation from applying. Do not unlink or replace the lock inode while a process may use it. It does not coordinate nodes or close SSH admission.

Privileged SSH key/known-host publication requires an absolute home base with root-owned, non-symlink, non-group/other-writable components. Managed account UIDs must be 1000–64999. Each home and `.ssh` directory must belong to the resolved UID and not be group/other writable; `.ssh` should be mode `0700`. Unsafe existing ownership or modes fail closed. Repair only verified account directories with an explicit administrator procedure; do not recursively chown untrusted trees.

In the container image, `sshd` uses trusted DB-backed ingress-key lookup (`AuthorizedKeysCommand /app/goBastion --authorizedKeys %u`, `AuthorizedKeysFile none`). New SSH public-key admissions do not trust user-writable `authorized_keys` files. Lookup/bootstrap/DB failures fail closed, so database outages can prevent new SSH public-key logins; operators must retain console/`docker exec` or equivalent out-of-band recovery access. Reconciliation may still publish compatibility files, but it is not the SSH admission source in that configuration. Trusted lookup does not terminate established sessions or provide distributed atomic revocation.

The image build helper replaces conflicting global SSH directives and refuses active `Match` blocks or additional `Include` files before modifying the configuration. The standard Alpine `sshd_config.d/*.conf` include is accepted only when it matches no files. Custom SSH configuration requires explicit review to preserve the trusted key lookup and constrained ForceCommand.

## Recordings

Production recording storage uses an isolated layout: `root:gobastion 0751` for the archive root, `account:gobastion-auditors 02750` for account/server directories, and `account:gobastion-auditors 0640` for published files. The auditor group contains enabled nonsystem administrators; its GID must differ from `gobastion` and must not be any account's primary group. ACLs are unsupported. Live captures remain plaintext and require separate storage/backup protection.

Startup and sync check recording storage integrity before accepting sessions. If an inconsistency is detected, startup attempts a safe automatic metadata repair when possible: it creates a root-only backup outside the archive, applies the repair, and rolls back that account if the repair fails. Automatic repair backups are stored under `/var/lib/goBastion/recording-migrations/`. If repair is incomplete or unsafe, startup fails and details are logged server-side; session errors are generic to clients.

### Manual offline repair

Use root-only `recording-admin permissions` when an explicit offline repair is required. Stop every instance and every process that can write the archive before apply/rollback (disconnect all bastion SSH sessions). `--offline` is an operator assertion; local process checks do not prove that remote instances or other writers have stopped. The backup must be outside the archive in a protected root-owned parent and is created exclusively as root-owned mode `0600`.

```sh
recording-admin permissions plan --archive /app/ttyrec --user alice
recording-admin permissions apply --archive /app/ttyrec \
  --user alice --backup /secure/recording-permissions/alice.json --offline

# For an account whose OS identity is already absent, use --retired consistently.
recording-admin permissions plan --archive /app/ttyrec --user alice --retired
recording-admin permissions apply --archive /app/ttyrec \
  --user alice --backup /secure/recording-permissions/alice.json --offline --retired
recording-admin permissions rollback --archive /app/ttyrec \
  --user alice --backup /secure/recording-permissions/alice.json --offline --retired
```

In Docker, run the tool as root inside the container or in a one-shot maintenance container mounting the same recording volume. The archive path is the container path (typically `/app/ttyrec`), and the backup must be written outside that archive:

```sh
docker exec -u 0 BASTION-service sh -c \
  'mkdir -p /root/recording-permissions && chmod 700 /root/recording-permissions'
docker exec -u 0 BASTION-service /app/recording-admin permissions plan \
  --archive /app/ttyrec --user alice
docker exec -u 0 BASTION-service /app/recording-admin permissions apply \
  --archive /app/ttyrec --user alice \
  --backup /root/recording-permissions/alice.json --offline

# List accounts present in the archive:
docker exec -u 0 BASTION-service ls -1 /app/ttyrec
```

Copy the backup out of the container if needed (`docker cp`) and keep it protected. Repeat for each affected account. If a plan fails, do not force manual recursive `chown`/`chmod`; inspect the reported archive metadata and keep the backup/rollback path available. An interrupted apply can be retried with the same validated backup; rollback restores recorded prior metadata. This procedure changes metadata only and does not encrypt existing recording contents.

An interrupted apply can be retried with the same validated backup; backups are not overwritten. Rollback restores recorded prior metadata and can restore insecure permissions. Keep the archive offline until the cause is fixed and secure metadata is reapplied. Retired account names and UIDs remain reserved while archive history exists. ACLs and ambiguous/reassigned identities require separate offline repair. This procedure changes metadata only and does not encrypt existing recording contents.

## Account lifecycle and helper compatibility

Account modify/expire/unexpire commits policy and then calls the privileged single-user reconciliation helper. A helper failure requires inspection of local account state, SSH files, sudo policy, auditor membership, and the revocation retry journal before considering the node reconciled. Pending auditor revocations are stored under `/run/gobastion/recording-revocations`; do not delete retry markers to bypass a failure. Account deletion requires zero registered target sessions and no unresolved pending recordings. Drain ingress and all instances first; review stale session rows rather than discarding them. Deletion retains the native account/home as an identity reservation, and database history reserves the login name. Do not use native `deluser` or reuse reserved names/UIDs. A local failure after DB compensation may leave host state changed; keep the node drained and reconcile the intended state.

Deploy the Go binary and helper scripts together. Legacy adduser/password/chown/sudoers scripts delegate to root reconciliation; native account creation is performed within that path and managed native deletion is refused. Administrator role does not create per-user raw-helper sudo grants. Root sync removes only an exact recognized historical goBastion per-user policy and preserves unexpected operator policies for review. The global `/etc/sudoers.d/gobastion-session` policy and application RBAC provide the managed entrypoints. `gobastion-session` is a reserved managed name; existing records with that name require reviewed offline identity repair. Binary and helper upgrades must be coordinated.

## Observability

See [Observability](OBSERVABILITY.md) for exporter settings, endpoint authentication, metric coverage, tracing, and deployment-template limits. Exporter readiness is not SSH readiness or a drain signal for user sessions. Optional tracing uses bounded queues and can drop telemetry during outages; it is not an audit-delivery mechanism.
