# Security and Production Gap Analysis

## Scope

This document compares the current `goBastion` implementation (repository state
as audited) with the security and operational capabilities expected from a
production-grade SSH/database bastion, using OVH The Bastion as the reference
model where comparable.

**Reference verification note:** OVH The Bastion's source and documentation were
not fetched from the network during this audit. Comparisons are based on
well-known OVH The Bastion capabilities (OSH command model, group/ACL model,
ttyrec recording, `--osh` administrative interface, MFA/TOTP, realms concepts,
restricted commands, per-access constraints) and on the current goBastion
codebase/docs. Any comparison that could not be verified against the reference
repository is stated as unverified.

## Legend

- **Implemented:** present in the codebase. This does not imply production
  validation.
- **Partially implemented:** some controls exist; significant gaps remain.
- **Missing:** not implemented.
- **Not applicable:** outside current scope or not a direct equivalent.

## Summary

`goBastion` has substantial hardening already in place: versioned authenticated
encryption for persisted application secrets (`gob:v2`), an offline
`secret-migrate` workflow, NsJail-isolated database clients with a privileged
broker, descriptor-relative SSH publication for root-reconciled files,
recording namespace separation and offline `recording-admin` sealing/verification,
structured audit logging, observability hooks, and extensive regression tests in
security-sensitive areas.

The main remaining security gaps are: **direct control-plane secret and DB
exposure to ForceCommand session processes**, **established-session and
cross-node revocation limits** despite trusted DB-backed admission for new SSH
connections, **live recordings are not cryptographically protected end-to-end**
(offline sealing exists), **instance-scoped session/admission state without
distributed coordination**, and **incomplete disaster-recovery/WORM/remote audit
delivery guarantees**.

---

## Gap Register

| ID | Domain | Current behavior | Relevant source files / functions | Security or operational impact | OVH comparison (unverified where noted) | Risk rating | Status |
|---|---|---|---|---|---|---|---|
| G1 | Privilege separation / secret management | `sshd` uses `ForceCommand /usr/bin/sudo -n /usr/local/sbin/gobastion-session`. The root wrapper copies bootstrap configuration to a mode-0600 temporary file, opens it as inherited FD 3, unlinks the file, and starts `/app/goBastion` as the SSH user. Secrets are not in the Go process's initial environment. The application reads and closes FD 3, temporarily loads bootstrap values into its environment, then unsets `DB_DSN` and encryption-key variables after database connection/keyring initialization and before starting session child processes. The session process retains its DB handle and loaded keys in memory. `internal/secretbroker` offers peer-UID checks and allowlisted operations, but ForceCommand session paths do not use it. DB client sessions use a separate privileged supervisor/broker/NsJail path. | `Dockerfile`, `entrypoint.sh`, `scripts/sudo/gobastion-session.sh`, `cmd/goBastion/main.go`, `internal/secretbroker/*`, `internal/session/db_supervisor.go`, `internal/dbsandbox/*`, `docs/architecture/adr-001-privilege-separation.md` | The bootstrap FD is briefly available to the session process during startup. Code executing within the session process can access retained keys, the DB handle, and data allowed to its DB connection. Shared SQLite/local DB-file exposure remains a separate concern. Clearing environment variables reduces their inheritance by later child processes but does not isolate memory or database access. | OVH The Bastion separates OSH/plugin execution concerns differently (Perl/OSH model); direct parity unverified. | High | Partially implemented (FD bootstrap and child-environment cleanup; session process still holds DB access and key material) |
| G2 | SSH authentication / key validation / revocation | Ingress keys are stored in DB and reconciled to user `~/.ssh/authorized_keys` for compatibility/administrative purposes. Container sshd sets `AuthorizedKeysFile none` and uses `AuthorizedKeysCommand /app/goBastion --authorizedKeys %u` as root to load canonical keys for enabled, non-system users with non-expired keys. Lookup/DB/bootstrap failures fail closed for new public-key admissions. Admission policy refresh and active-session termination are separate. | `internal/authkeys/*`, `cmd/goBastion/main.go`, `Dockerfile`, `scripts/test-sshd-authorized-keys.sh`, `internal/utils/sync/sync.go`, `docs/security/SECURITY_AUDIT.md` | DB outage can block new public-key logins. Established sessions are not terminated when an ingress key is revoked; distributed/session-level revocation is incomplete. | OVH The Bastion supports centralized account/key management and OSH workflows; exact OpenSSH key-command mechanism parity unverified. | Medium/high (residual active-session and distributed revocation limits) | Partially implemented (trusted lookup for new admissions) |
| G3 | Audit trail / session recording confidentiality & integrity | SSH/DB recordings are published as compressed plaintext (`.ttyrec.gz`). Publication uses atomic paths, per-recording locks, recovery for interrupted spools, and separated namespace permissions. `Publish` emits a best-effort SHA-256 integrity sidecar (`*.integrity.json`); `VerifyPublishedIntegrity` and `recording-admin verify-published --input <recording>` check it. Offline `recording-admin` sealing provides authenticated encryption, Ed25519 signatures, hash verification, and decryption for sealed archives. There is no live AEAD capture, signed live provenance, or automatic remote S3/WORM archival. | `internal/recording/publish.go`, `internal/recording/integrity.go`, `cmd/recording-admin/*`, `docs/security/SECURITY_AUDIT.md` | Sidecars do not provide confidentiality, signed provenance, chunk ordering guarantees, or durable remote delivery. Live capture/publication remains sensitive. Sidecar commit is best-effort after primary publication. | OVH The Bastion records sessions (ttyrec) and supports operational controls; exact cryptographic/WORM pipeline parity unverified. | High | Partially implemented (integrity sidecar + verify-published command) |
| G4 | Active session revocation / distributed session control | `active_sessions` tracks sessions per instance. Admission refreshes policy on command paths. DB sessions have an actor monitor that cancels on account authorization or selected target-grant changes, as well as query failures/timeouts. Privileged sync terminates local OS processes for disabled users (`TerminateUserSessions`/`pkill -KILL -u <uid>`) and removes ingress keys/sudoers state. Account disable/expiry flows call reconciliation helpers. No cluster-wide lease/heartbeat protocol or global admission coordination exists; not every grant/key/role change terminates every established SSH session. | `internal/models/active_session.go`, `internal/session/*admission*`, `internal/session/db_actor_monitor*`, `internal/utils/sync/*`, `internal/osadapter/linux.go`, `internal/commands/account/*`, `docs/architecture/HA_DESIGN.md` | Termination occurs on the local node during sync/reconciliation. Multi-node stale sessions and races with admission remain possible. | OVH supports session/account controls; multi-node distributed enforcement parity unverified. | High | Partially implemented (local account-disable handling; distributed/global revocation missing) |
| G5 | High availability / multi-node consistency | PostgreSQL is supported; root startup migrations use PostgreSQL advisory locks among participating versions. Active sessions and limits are instance-scoped. SQLite is local/standalone; MySQL migration locking differs. Full node registration, health, drain, and maintenance state are not present. | `internal/db/*`, `docs/architecture/HA_DESIGN.md`, `docs/architecture/ARCHITECTURE.md`, `sql/postgres.sql`, `sql/mysql.sql` | Multiple nodes can share DB state but lack coordinated admission, draining, failover semantics, and global session guarantees. | OVH deployments can be scaled operationally; exact built-in multi-node coordination parity unverified. | High | Partially implemented |
| G6 | Disaster recovery / backup integrity | Encrypted logical DB export/import exists (`--dbExport/--dbImport`, `DB_EXPORT_KEY`). Secret migration has a backup flow, and recording admin has offline archive tools. Full restore drills, point-in-time recovery guidance by backend, key recovery validation, compatibility matrix, RPO/RTO measurement, and corrupted-backup detection coverage are not established here. | `internal/db/export.go`, `internal/startup/startup.go`, `cmd/secret-migrate/*`, `cmd/recording-admin/*`, `docs/operations/OPERATIONS.md` | Backups may be incomplete or unrestorable, or lack key material/recording context. Recovery objectives are unproven. | OVH operational guidance exists; direct feature parity unverified. | Medium | Partially implemented |
| G7 | Runtime/container hardening | The Docker image configures SSH hardening, trusted `AuthorizedKeysCommand`, ForceCommand, managed account groups, and NsJail support for DB isolation. The Compose example is illustrative and keeps the root filesystem writable because the current entrypoint modifies system account files and `/goBastion.log`; it does not enable `no-new-privileges` because SSH sessions invoke a setuid `sudo` wrapper. Capability, seccomp/AppArmor, and runtime compatibility have not been established by this example. | `Dockerfile`, `entrypoint.sh`, `profiles/*`, `deploy/docker-compose.hardened.yml`, `docs/operations/production-hardening.md`, `scripts/sudo/*` | Incorrect runtime restrictions can break startup or prevent SSH sessions from reaching the constrained helper. DB outage blocks new SSH public-key admissions; operators need out-of-band recovery access. | OVH has deployment hardening guidance; parity unverified. | High | Illustrative configuration only; host/runtime compatibility unverified |
| G8 | Security assurance / CI DevSecOps | The repository contains Go tests, integration targets, scanner triage documentation, and a Gosec findings inventory. CI coverage for fuzzing, dependency/container scanning, SBOM, signing, and provenance is not established by this audit. | `*_test.go`, `docs/security/SCANNER_TRIAGE.md`, `docs/security/GOSEC_2_30_0_FINDINGS.md`, `docs/development/VALIDATION.md`, `Dockerfile` isolation-test target | Parser, authorization, crypto, and concurrency regressions may escape without systematic adversarial coverage and release-integrity controls. | OVH has mature operational practices; CI parity unverified. | Medium | Coverage varies by path; no release-assurance claim is made here |
| G9 | Observability / operational readiness | Structured logs, optional OTLP tracing, loopback metrics exporter, and observability deployment assets exist. Health/readiness/liveness semantics, alert rules, and SLO-oriented metrics for revocation, recording integrity, and node state are not fully productized. | `internal/observability/*`, `internal/telemetry/*`, `cmd/observability/*`, `deploy/observability/*`, `docs/operations/OBSERVABILITY.md` | Operators may detect security or availability failures late or lack actionable signals. | OVH exposes operational telemetry; parity unverified. | Medium | Partially implemented |
| G10 | Identity federation / JIT / SSH certificates / policy as code | Local accounts, roles, groups, TOTP/password/PIV flows, restricted command grants, and realm relay metadata exist. OIDC/LDAP/SAML provisioning, ticketed JIT approval, short-lived SSH CA principals, declarative admin API, and authenticated cross-bastion federation are not established as security-grade features. | `internal/commands/realm/*`, `internal/mfa/*`, `internal/utils/piv/*`, `internal/models/*`, `docs/security/SECURITY_AUDIT.md` | Enterprise lifecycle workflows remain manual. Realm metadata can be mistaken for authenticated federation. | OVH has realms and mature access workflows; specific feature parity unverified and architecture differs. | Medium | Missing or partial |
| G11 | Advanced database PAM | DB sessions use a privileged supervisor, NsJail, broker-owned upstream TLS verification, and restrictions for specific clients. Ephemeral DB credentials, fine-grained DB policy, protocol-aware SQL auditing, and centralized access reviews are not fully implemented. Terminal capture is not semantic SQL audit. | `internal/session/db_supervisor.go`, `internal/dbsandbox/*`, `cmd/dbworker/*`, `internal/utils/dbConnector/*` | Credential lifetime and DB-layer intent visibility are limited; compliance claims would be overstated. | OVH has strong SSH focus; DB PAM parity differs/unverified. | Medium | Partially implemented |

---

## Residual security limits

Trusted DB-backed lookup controls admission for new SSH public-key sessions in
the container image. It does not terminate established sessions or coordinate
admission and revocation atomically across nodes. ForceCommand session processes
still receive DB and encryption bootstrap values, although the application clears
those environment variables before launching child processes. Live recordings
remain plaintext and local; their SHA-256 sidecar is best-effort integrity
metadata, not authenticated provenance or confidentiality. These limits are
described alongside current behavior in the [threat model](THREAT_MODEL.md),
[security audit](SECURITY_AUDIT.md), and [operations guide](../operations/OPERATIONS.md).
