# Security controls and limitations

## Control-plane access

ForceCommand processes access the control-plane database and receive the egress
keyring. SQLite files and WAL are writable by the shared bastion group. Code
running locally as a bastion Unix account can therefore affect database integrity
and access secrets available to that process. A PostgreSQL backend does not
remove direct session access to database credentials and encryption keys.

This local-code/filesystem threat is distinct from an SSH client restricted to
the ForceCommand protocol. Isolation of the database and keys from session
processes is not implemented.

## SSH and privileged operations

The image configures public-key SSH authentication, disables root/password SSH
login and agent/TCP forwarding, and uses a ForceCommand session helper. The
container sshd configuration sets `AuthorizedKeysFile none` and uses
`AuthorizedKeysCommand /app/goBastion --authorizedKeys %u` as root. The trusted
key lookup returns only canonical ingress keys for enabled, non-system accounts
whose keys are not expired; database/lookup failures fail closed for new SSH
public-key authentication. User-writable `authorized_keys` files are not
consulted by sshd in that configuration.

Session policy is refreshed before command dispatch. Authentication supports the
configured password, TOTP, PIV and recovery-code flows; an enabled TOTP profile
with an empty seed is refused.

Privileged helpers delegate account requests to root reconciliation, which reads
database policy under a node-local lock. Root creation uses fixed native
commands; native deletion of managed identities is forbidden. SSH publication
uses descriptor-relative traversal, no-follow opens and UID/GID checks. It does
not recursively change ownership through user-controlled trees. Reconciliation may
still publish compatibility files, but sshd admission must not rely on them.

The global sudo policy is `/etc/sudoers.d/gobastion-session`. Managed names
`gobastion`, `nobody` and `gobastion-session` are reserved. Root sync removes only
an exact recognized five-line legacy goBastion per-user policy; unrelated policy
files are retained and require operator action. Administrator role does not
create direct raw-helper sudo grants. Deploy matching binaries and helpers
according to the [operations guide](../operations/OPERATIONS.md).

Trusted key lookup improves revocation of new SSH public-key admissions; it does
not by itself terminate established sessions. Database policy changes, local
publication, and session/admission state remain separate operations; distributed
atomic revocation is not implemented. During a database outage, fail-closed key
lookup can prevent new SSH public-key logins; operators need console or
`docker exec` recovery access.

## Persistent secrets

Nonempty application-secret operations require a canonical base64 AES-256
`EGRESS_ENC_KEY`. Ciphertext uses `gob:v2` envelopes that authenticate the version
and key ID. Historical keys support authenticated decryption; ordinary reads and
writes do not fall back to plaintext.

The offline inventory covers personal/group egress private keys, personal/group/
guest database passwords, SSH host private keys and TOTP secrets, including
soft-deleted records. `secret-migrate` performs explicit conversion and rotation
with an encrypted logical backup before apply. Its session-count check does not
block admissions: every instance must remain stopped. Backup interruption,
production-scale memory use and backend rollout need operational handling.

Field encryption does not encrypt raw database files, WAL, physical backups,
live recordings or storage media. `DB_EXPORT_KEY` protects logical exports
separately. Older binaries cannot read v2 records; mixed-version rollback is
unsupported. See operations for key retention, migration and restore procedures.

## Database clients

A root supervisor independently checks the caller, account policy, target
permission, CIDR, expiry and MFA. It launches only supported psql, MariaDB and
Redis clients through the broker and NsJail. Target passwords stay in the
broker rather than the native client's environment, arguments or configuration.
Upstream TLS verifies the original target identity; there is no plaintext or
unverified fallback.

Actor monitoring cancels a session on missing, disabled or system account state,
query failure or timeout. Cancellation also returns failure when a connector
suppresses the cancellation error. Drivers must honor context cancellation.
The actor monitor does not refresh target grants or implement cluster-wide
revocation. Namespace, seccomp and AppArmor enforcement depend on the deployed
host and container configuration.

## Recordings

Live SSH/DB captures are compressed plaintext. The archive root is root:gobastion
0751; account/server directories are account:gobastion-auditors 02750 and
published files are account:gobastion-auditors 0640. Only enabled nonsystem
administrators join the separate auditor group; SuperOwner alone does not grant
playback. Unsupported ACLs, unsafe ownership and shared legacy layouts cause
refusal. Permission migration is an explicit offline operation.

Auditor revocation removes group membership and terminates/verifies old UID
processes, with a durable local retry journal. Account retirement requires zero
registered sessions and no unresolved pending captures, seals the recording
boundary as root and retains the Unix UID/name reservation. These controls do
not protect captures from their own UID or root, nor make admission atomic.

`recording-admin` provides offline authenticated encryption, Ed25519 signatures,
hash verification and decryption using recording keys independent of the egress
key. The encrypted format is not integrated with live capture. Automatic remote
S3/WORM archival, trusted capture provenance and retention enforcement are absent.

## Audit and telemetry

Structured events carry session/request correlation. Redaction covers recognized
secret flags, credential-bearing URLs/DSNs and PostgreSQL password assignments;
structured diagnostic errors expose their class instead of raw credential fields.
Arbitrary command output, unknown secret syntax and recording content can still
contain sensitive data.

The runtime rejects OTLP authentication-header secrets; remote collector
credentials belong in the collector. Complete event coverage, durable remote
log delivery and end-to-end telemetry retention are not established. See
[observability](../operations/OBSERVABILITY.md).

## Unsupported guarantees

Active-active consistency, coordinated drain/failover, transparent session
migration, scoped JIT SCP/SFTP tickets and authenticated realm federation are
not implemented. Realm relay metadata does not authenticate qualified remote
identities. TOTP replay/authorization coverage and complete host-profile,
protocol, disaster-recovery and multi-node testing remain incomplete.

The [threat model](THREAT_MODEL.md) identifies assets and assumptions.
[Scanner triage](SCANNER_TRIAGE.md) and the
[Gosec inventory](GOSEC_2_30_0_FINDINGS.md) describe outstanding static analysis.
