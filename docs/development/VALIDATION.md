# Validation

Recorded checks for the implementation: 2026-11-09, Go 1.27.3. Go package
concurrency was limited to `-p 1`, with `GOMAXPROCS=2`.

## Check matrix

| Check | Result | Scope |
| --- | --- | --- |
| `go test -p 1 ./...` | Pass | Full ordinary package suite; gated root/integration tests run separately. |
| `go test -race -p 1 ./...` | Pass | Full ordinary suite with race detection. |
| `go build -p 1 ./...`, `go vet -p 1 ./...` | Pass | All packages. |
| `make lint` | Pass, zero issues | golangci-lint 2.15.0. |
| `go mod verify` | Pass | Module download integrity. |
| govulncheck 1.9.0 | Pass | No vulnerabilities reported. |
| Gitleaks 8.30.1 | Pass | Working tree with narrow fixture exceptions; no history rescan in this check. |
| Gosec 2.30.0 | 83 findings on 2026-11-09 | Historical snapshot: 38 HIGH / 45 MEDIUM scanner labels; the [current inventory](../security/GOSEC_2_30_0_FINDINGS.md) records the latest scan. |
| Disposable root suite | Pass | Recording isolation, administrator access/revocation, retirement, ACL refusal, migration/resume/rollback, policy cleanup and reconciliation. |
| PostgreSQL integration | Pass | Secret migration/rotation/export, migration locks/cancellation, boolean conversion and concurrent observations. |
| Runtime-stage integration | Pass | PostgreSQL/MariaDB/Redis clients, sudo, NsJail, broker TLS/identity restrictions, recording/cancellation, live sync and account/group revocation. |
| Documentation/configuration | Pass | Markdown links/fences, shell syntax, agent TOML and workflow lint. |

## Integration entry points

```sh
GOB_TEST_RECORDING_EXPOSURE_AUDIT=1 scripts/test-secret-root.sh
scripts/test-secret-postgres.sh
scripts/test-sshd-authorized-keys.sh
```

The root runner uses a disposable container. Never set its root-test gates when
running test binaries against host `/etc`, `/run` or real account homes. The
runtime DB-client environment is the `isolation-test` target in `Dockerfile`;
its scenarios are in `scripts/test-db-isolation.sh` and `scripts/test-db-supervisor.sh`.

Local recording and broker tests require trusted temporary-directory ancestors.
A root-owned shared temporary directory must have its sticky bit set. Select a
suitable `TMPDIR` when the host's default directory fails these checks; do not
weaken the production guards for fixtures. Keep the path short enough for Unix
socket names, whose length is limited by the operating system.

## Coverage limits

The runtime-stage check used host-built Go binaries with the Docker runtime and
test stages. It did not build the original SDK stages or perform an image/SBOM
scan. Outer AppArmor was unconfined for this dedicated check; the host-loaded
AppArmor profile, SELinux and the complete host matrix remain unverified.

## Focused verification scope for the current changes

The commands below identify relevant coverage; this section does not record a
result. Run them in the repository before reporting validation outcomes:

| Command | Scope and environmental requirements |
| --- | --- |
| `go test ./internal/authkeys ./internal/secretbroker -count=1` | DB-backed ingress-key filtering and local broker behavior. |
| `scripts/test-configure-sshd.sh` | Unprivileged checks of the image's SSH configuration transform, including conflicting directives and refusal of conditional configuration. |
| `docker run --rm --network none --entrypoint /bin/sh -i <fresh-runtime-image> < scripts/test-security-runtime.sh` | Disposable runtime smoke test for root-only audit collection, kernel sender identity, refusal of direct audit-file access, protected bootstrap through the sudo session wrapper, account process revocation and retirement preserving UID/home/recording namespace. Requires a fresh image with no existing DB/bootstrap state. The Security workflow runs this script against both locally built runtime variants with bounded tmpfs storage. It does not exercise the normal entrypoint, DB-client isolation or multi-node coordination. |
| `scripts/test-sshd-authorized-keys.sh` | Disposable real-sshd admission and product ForceCommand checks: bootstrap, command status, invalid `-osh` command handling, interactive shell lifecycle, password MFA acceptance/refusal and redaction, encrypted egress-key generation, child-environment hygiene, privileged account creation, encrypted TOTP and session cleanup. Uses a real local SSH target for direct-session revocation, a native ProxyJump hop, rsync with splash on/off, historical SCP upload/download and SFTP with a pinned proxy host key; transferred payloads are compared. `GOB_TEST_EXTERNAL_TARGET=1` adds a separate SSH target container on a disposable bridge network. Recorded-session revocation is optional via `GOB_TEST_TTYREC_BIN` (see below). Uses the Compose example's capability set. Requires Docker and network access to install OpenSSH, rsync, sudo and su-exec. Does not exercise a deployment target outside Docker or NsJail. |
| `scripts/test-mfa-backends.sh` | Disposable SQLite, PostgreSQL and MariaDB checks of TOTP consumption/replay, concurrent attempts and fail-closed revocation. MariaDB exercises the MySQL dialect; Oracle MySQL is selectable separately. Each backend container is cleaned before the next one starts. |
| `scripts/test-export-lifecycle-backends.sh` | Disposable PostgreSQL and MariaDB fixtures for held encrypted-export snapshots, concurrent writes/deletes, cancellation and connection return. `GOB_EXPORT_BACKENDS` can select one backend. SQLite WAL retention/truncation is covered by `TestSQLiteExportSnapshotRetainsWALUntilReleased`. The MySQL fixture checks snapshot consistency and pool release; it does not use `information_schema.innodb_trx` as a release oracle. |
| `GOB_EXPORT_LOAD_MEASUREMENT=1 go test ./internal/db -run '^TestSQLiteExportBoundedLoadMeasurement$' -count=1 -v` | Opt-in, bounded SQLite measurement of writer latency, WAL retention/truncation, pool release, output volume and process-wide Go memory during a held export snapshot. Uses a direct export key and discarded output; its figures do not establish deployment capacity. |
| `go test ./internal/utils/sync ./internal/commands/account -count=1` | Account reconciliation, including local process termination on disabled-user sync. |
| `go test ./internal/recording ./cmd/recording-admin -count=1` | Recording publication sidecar, tamper detection, and `verify-published` CLI behavior. |
| `go test ./cmd/goBastion -count=1` | Main command package, including authorized-key bootstrap behavior. |
| `go test ./...` and `go test -race ./...` | Broader package and concurrency coverage; these do not replace privileged root, SSH runtime, database, or multi-node rehearsals. |

The real-sshd script also checks invalid `-osh` commands through ForceCommand for
nonzero status, unchanged group/grant/alias state and synthetic credential
redaction in output and local logs. Its interactive-shell fixture uses a real
PTY to run a command, exit normally and check process and registry cleanup.
Password MFA is exercised with a remote PTY after the challenge appears;
an invalid factor is rejected, the configured factor is accepted, and the
synthetic factor is checked absent from output and local logs.
The optional second-container target checks Docker DNS/bridge transport, an
authorized egress key and successful command output. Its bind-mounted public
key fixture disables `StrictModes` only in the disposable target sshd.

To include the recorded-session transport and child-process shutdown scenario,
set `GOB_TEST_TTYREC_BIN` to an executable built from the pinned `ovh-ttyrec`
revision and apply `scripts/patches/ovh-ttyrec-parent-hup.patch` before building.
The pin and patch application are defined in the `ttyrec-builder` stage of the
Dockerfile. The script copies the supplied binary into its disposable test
container. Without this variable, the recorded-session scenario is skipped;
the direct-session revocation checks still run.

Complete SSH workflow coverage, full-image Docker runtime hardening,
multi-node/HA, disaster-recovery measurements, MySQL offline secret
migration, S3/WORM retention, rolling upgrades, and measured backup/restore
RPO/RTO require separate environment-specific verification. Prometheus, Grafana,
and Collector files are examples without a pinned-distribution deployment test.
See [security limitations](../security/SECURITY_AUDIT.md) for current runtime
boundaries.
