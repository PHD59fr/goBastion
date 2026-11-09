# Availability and lifecycle behavior

This document describes the current multi-instance and lifecycle behavior. goBastion does not implement active-active high availability, cluster-wide admission control, or a coordinated drain protocol.

## Database and migrations

Root invocations perform schema migration except `--sync`, `--syncUser`, and `--dbSession`; ForceCommand sessions skip migrations. PostgreSQL root startup migrations use a fixed session advisory lock on a pinned connection. The lock coordinates participating goBastion migrators using the same key, not arbitrary DDL or older binaries. MySQL startup migrations have no distributed lock. SQLite uses one connection per process, WAL, and a busy timeout, but does not serialize the full migration sequence across processes. Use one local SQLite instance; shared multi-host SQLite is not qualified.

## Instance configuration and sessions

Instance configuration is stored in `bastion_instances`. `INSTANCE_ID` or persisted/bootstrap configuration identifies the instance. Deployments must provide unique stable IDs; the record has no process-incarnation lease or heartbeat.

Active SSH sessions record an instance ID and local PID. Session limits and stale-process cleanup are instance-scoped, and PID checks are meaningful only on the local host. There is no cluster-wide session limit or atomic gate that rejects admissions during shutdown. In the container image, `entrypoint.sh` stops `sshd` on shutdown and waits up to `DRAIN_TIMEOUT_SECONDS` (default 30) for active managed user sessions before stopping background services; this is a local, best-effort drain and not a coordinated multi-node drain, readiness gate, or guarantee for all session state.

## Policy changes and local reconciliation

Account policy updates use transactions and row locks for administrator records on backends that support row locking; SQLite has different locking behavior. These operations do not coordinate admission across nodes.

Startup, manual `--sync`, periodic sync, and the privileged single-user helper reconcile local host state. Participating root reconciliation paths share a node-local lock and fail closed if it cannot be acquired. The lock is local to the node and is not a database/filesystem transaction or distributed lock. Account database changes and local publication remain separate operations; admission and other nodes can observe or apply state at different times. Deletion requires zero registered sessions and no unresolved pending recordings, terminates and verifies local target processes, removes local grants, and retains the Unix identity reservation. This does not eliminate admission races or establish cluster-wide revocation.

## Deployment implications

Use unique instance IDs. For multiple nodes, use PostgreSQL for the shared control-plane database and allow only one migration owner for MySQL, SQLite, mixed versions, or versions that do not participate in PostgreSQL migration locking. Treat shutdown as potentially interrupting active sessions. Coordinate secret-key changes and offline migrations across all instances. External orchestration must not interpret exporter readiness as SSH readiness or a completed drain.
