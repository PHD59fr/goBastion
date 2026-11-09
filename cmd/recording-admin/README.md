# Offline recording administration

`recording-admin` is an explicit root-only console tool. It refuses SSH sessions,
does not read `EGRESS_ENC_KEY`, and does not change the live recording pipeline.
Existing live recording spools remain plaintext. A trusted capture integration
is not available.

Build with `go build -o recording-admin ./cmd/recording-admin` and install the
binary root-owned with mode `0700`. Private PEM files must be service-owned and
unreadable by group/other; use PKCS8 for Ed25519 signing/RSA recipient private
keys and PKIX for public keys. RSA recipients must be 3072-8192 bits with exponent
65537. Signing keys must be dedicated to recording provenance. Keep recipient
decryption keys outside the capture service whenever its role permits that.
Private-key leaf symlinks are refused; point at the actual protected secret file.
Key files must contain exactly one canonical PEM block (standard 64-column
base64, LF line endings and final LF), starting at the first byte.

The output parent directory must be service-owned without group/other write
access. Output files are exclusively created with mode `0600`, synchronized, and
published with an exclusive hard link on the same filesystem; existing files or
symlinks are never overwritten. Decryption copies bounded ciphertext into a
private unlinked snapshot, verifies before decrypting, then publishes only after
all checks succeed. A filesystem failure during the final directory sync may
leave a complete output whose durability could not be confirmed; inspect it
before retrying. Plaintext output to stdout is not supported.

```sh
recording-admin seal \
  --input /secure/legacy/session.ttyrec --output /secure/archives/session.gobrec \
  --signing-key /secure/keys/recording-signing.pk8.pem \
  --recipient /secure/keys/auditor.public.pem \
  --recipient /secure/keys/recovery.public.pem \
  --session-id imported-session-1 --bastion-id original-bastion \
  --protocol ssh --account alice --target deploy@host.example:22 \
  --started-at 2026-11-08T01:02:03Z

recording-admin verify --input /secure/archives/session.gobrec \
  --verify-key /secure/keys/recording-signing.public.pem

recording-admin decrypt --input /secure/archives/session.gobrec \
  --output /secure/replay/session.ttyrec \
  --verify-key /secure/keys/recording-signing.public.pem \
  --recipient-key /secure/keys/auditor.pk8.pem
```

Each successful command prints only the canonical public signed manifest. `seal`
always records `capture_outcome=imported`: the operator-supplied historical
session/bastion/protocol/timestamp fields are assertions made during import, not
proof of historical capture provenance or completeness. There is no CLI flag to
claim normal session completion. Compression defaults to `none`; `--compression
gzip` declares already compressed input and does not repair incomplete gzip.

Input defaults to a 1 GiB limit; raise `--max-input-bytes` explicitly for larger
administrative operations and budget space for ciphertext snapshots and private
output staging. Verification requires only trusted signing public keys. Retain
historical verification keys and needed recipient private keys for old archives;
recipient removal cannot revoke previously unwrapped keys or copied plaintext.
Unfinished encrypted captures cannot be finalized under a different header-bound
signing ID without a separately designed recovery protocol.

## Offline archive permissions repair

`permissions plan` inventories metadata for one account archive and prints a
JSON plan; it does not change files. Apply and rollback require root, a protected
metadata backup path outside the archive, and `--offline`. Before either
operation, stop every goBastion instance and all sessions, capture processes,
and ingress or archive writers that can touch this volume. `--offline` records
the operator's assertion; the command only checks for local processes running
as the account UID and cannot establish that other instances or writers have
stopped.

Startup checks recording storage integrity and, when safe, attempts automatic
metadata repair with a backup and rollback on failure. If automatic repair is
incomplete or unsafe, startup fails and details are logged server-side. Use this
command for explicit offline repair when required.

```sh
recording-admin permissions plan --archive /app/ttyrec --user alice

# For a deleted local account, add --retired to plan, apply, and rollback.
recording-admin permissions plan --archive /app/ttyrec --user alice --retired
recording-admin permissions apply --archive /app/ttyrec \
  --user alice --backup /secure/recording-permissions/alice.json --offline --retired
recording-admin permissions rollback --archive /app/ttyrec \
  --user alice --backup /secure/recording-permissions/alice.json --offline --retired
```

In a container deployment, the archive is typically mounted at `/app/ttyrec`; run
the command as root (`docker exec -u 0 ...`) or from a one-shot maintenance
container with the same volume mounted, and store the backup outside the archive.

For an account that still exists locally, omit `--retired`. The backup parent
must be root-owned and not writable by group/other; the backup is exclusively
created root-owned with mode `0600`. Keep it protected and retain it for
rollback. If apply stops partway through, rerun the same apply command with the
same backup to resume; it is not overwritten. Rollback restores the recorded
old metadata, which can restore insecure permissions, so keep the archive
offline until the underlying issue is fixed and the secure migration is
reapplied. Rollback does not remove the backup.

The retired form requires that the account no longer exist locally and uses
the prior recording UID from the inventory; reserve that name and UID so they
are not reassigned while archived history remains. Legacy archives missing the
OS account therefore require `--retired`. ACLs are not supported: an extended
ACL causes refusal and needs separate explicit offline repair. The operation
changes filesystem metadata only; recording contents, including legacy
plaintext recordings, are unaffected. This is an administrative migration
mechanism, not an acceptance or production-readiness claim.
