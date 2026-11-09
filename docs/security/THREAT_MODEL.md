# Threat model

## Scope and assets

The scope is sshd/ForceCommand, privileged helpers, the control-plane database,
SSH/DB targets, recordings, telemetry and realm relay configuration. Assets
include account and grant state, ingress/egress keys, target credentials, MFA
secrets and recovery codes, encryption/signing keys, active sessions and audit
records.

Trust boundaries separate remote clients from sshd, session users from root
helpers, jailed clients from the broker, the application from its database,
the bastion from targets, and runtime storage from operators/backups.

## Threats and current controls

| Category | Threat | Current controls and limits |
| --- | --- | --- |
| Spoofing | Stolen ingress key, forged user/source context, target impersonation or forged realm identity. | SSH public-key admission can use DB-backed `AuthorizedKeysCommand` lookup (enabled/non-system/non-expired keys only; fail closed on lookup errors). Configured MFA and target host/certificate checks apply. Authenticated qualified realm identities are unavailable. Local code has broader access than the ForceCommand protocol. |
| Tampering | Role/grant changes, raw DB writes, client argument injection or recording substitution. | Administrator transactions, fixed jailed clients, descriptor-based publication and spool locks constrain specific paths. Shared SQLite writes/direct session credentials expose the control plane. Same-UID/root recording tampering remains possible. |
| Repudiation | Denial of a command, policy change or recording access. | Structured correlated events and recording access logging exist. Durable remote retention and a trusted automatic signed-capture pipeline are absent. |
| Disclosure | Stored credentials, logs/configuration, recordings or another account's data. | Application-secret fields require versioned authenticated encryption; recording directories separate owners and administrators. Raw DB/WAL/backups, session keyrings and live plaintext recordings need separate protection. Redaction does not cover arbitrary output or unknown secret syntax. |
| Denial of service | Floods, DB locks/outages, exhausted jail slots, oversized traffic or full storage. | Instance-scoped limits, deadlines, cancellation, broker bounds and local locks apply. Distributed admission, coordinated drain and complete storage/failure handling are unavailable. |
| Privilege escalation | Unsafe sudo helper, sandbox escape, stale privileges or policy/admission race. | Root helpers reload DB state; recursive ownership mutation/raw administrator grants are absent. NsJail and seccomp constrain clients. Host enforcement and non-atomic cross-node/session revocation remain boundaries; trusted ingress lookup reduces but does not eliminate race/stale-session exposure. |

## Assumptions

- Operators protect the host, runtime, root configuration, database, key material
  and backups. Root/host compromise exposes the secrets they can access.
- The managed Unix UID range and database identities must not alias unrelated
  accounts. Retired names and UIDs remain reserved; ambiguity requires offline
  repair.
- Offline migrations require all instances and writers stopped. A session count
  or local process census is not a distributed admission lock.
- Target credentials have appropriate server-side privileges. The broker does
  not reduce the target account's database permissions.
- Deployment network/TLS policy, kernel namespace support, host-loaded profiles,
  clock synchronization and storage protection are operator responsibilities.

See [security controls and limitations](SECURITY_AUDIT.md) and
[availability behavior](../architecture/HA_DESIGN.md) for enforcement details.
