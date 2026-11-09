# Production hardening

This document describes deployment hardening measures for goBastion. It does not
replace host security baselines, backup validation, or operational rehearsals.

## Container/runtime

- Run with the minimal capabilities required by the validated image/runtime.
  Treat `deploy/docker-compose.hardened.yml` as an unvalidated example; its
  capability set has not been shown to support every host and NsJail workflow.
  `FSETID` preserves the required setgid bit when root provisions recording
  directories owned by account:auditors; omitting it can clear that bit even
  when `chmod` succeeds.
- The current image needs a writable root filesystem: startup updates `/etc`
  account files and `/goBastion.log`. Its SSH session path invokes a setuid
  `sudo` wrapper, so `no-new-privileges` prevents that path from working. The
  example leaves both controls disabled. Enabling either requires a compatible
  runtime design and validation first.
- The example bounds `/run` and `/tmp` tmpfs sizes and sets process, memory, CPU,
  and file-descriptor limits. These settings are starting values, not validated
  capacity guidance.
- Apply seccomp/AppArmor profiles compatible with NsJail and sshd. Load the
  repository profiles only after host validation (`profiles/Readme.md`).
- Set resource limits (PIDs, memory, CPU, file descriptors) to reduce denial-of-service impact.
- Preserve out-of-band recovery access (console/`docker exec`/host access):
  SSH public-key admission can fail closed on DB/bootstrap lookup errors.

## Secrets and data

- Provide a canonical base64 AES-256 `EGRESS_ENC_KEY` through a mounted secret
  file or protected secret store for persisted-secret operations. The Compose
  example requires `deploy/secrets/egress_enc_key` from the repository root
  (`./secrets/egress_enc_key` relative to the Compose file); create it locally
  and do not commit it. This directory is excluded from Git and the Docker build
  context. Keep `DB_EXPORT_KEY` separate. The example does not configure a
  database DSN secret file; `DB_DSN_FILE` is not supported by the current
  entrypoint.
- Protect SQLite files/WAL, PostgreSQL/MySQL credentials/backups, recording
  archives, and key material with storage controls; field encryption does not
  protect raw storage/backups/live recordings.
- Use trusted SSH host keys and distribute the stable SFTP proxy host key.

## SSH admission and revocation

- Container `sshd` uses DB-backed `AuthorizedKeysCommand` with
  `AuthorizedKeysFile none`. This prevents user-file key injection for new
  admissions and fails closed on lookup errors.
- This does **not** automatically terminate established sessions. Use
  account disable/expire flows, synchronization/session termination mechanisms,
  and distributed revocation procedures appropriate to your deployment.

## Recordings and audit

- Live recordings remain sensitive plaintext/compressed artifacts at capture time
  unless an explicit protected capture pipeline is configured. Protect storage
  and backups.
- Published recordings now include a best-effort SHA-256 integrity sidecar
  (`*.ttyrec.gz.integrity.json`). Verify with
  `recording-admin verify-published --input <recording>`. Missing sidecars or
  mismatches require investigation. The sidecar is not signed and does not
  provide confidentiality or authenticated provenance.
- Offline sealed archives (`recording-admin`) provide authenticated encryption/
  signatures for exported artifacts; they are not the same as live capture.

## Network and targets

- Restrict inbound SSH exposure, egress to authorized targets, and management
  interfaces. Run metrics on loopback or an authenticated internal network.
- Verify upstream DB TLS/certificates as configured; do not disable verification.

## Operations

- Test upgrades, key rotations, backup/restore, recording recovery, and account
  revocation in disposable environments before production.
- Monitor auth failures, authorization denials, admission errors, recording
  publication/recovery failures, DB connectivity, and node/session state.
- Review `docs/security/SECURITY_AUDIT.md` and `security-gap-analysis.md` for
  current limitations before claiming production readiness.
