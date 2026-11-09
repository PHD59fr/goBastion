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
| Gosec 2.30.0 | 83 findings | 38 HIGH / 45 MEDIUM scanner labels; see the [inventory](../security/GOSEC_2_30_0_FINDINGS.md). |
| Disposable root suite | Pass | Recording isolation, administrator access/revocation, retirement, ACL refusal, migration/resume/rollback, policy cleanup and reconciliation. |
| PostgreSQL integration | Pass | Secret migration/rotation/export, migration locks/cancellation, boolean conversion and concurrent observations. |
| Runtime-stage integration | Pass | PostgreSQL/MariaDB/Redis clients, sudo, NsJail, broker TLS/identity restrictions, recording/cancellation, live sync and account/group revocation. |
| Documentation/configuration | Pass | Markdown links/fences, shell syntax, agent TOML and workflow lint. |

## Integration entry points

```sh
GOB_TEST_RECORDING_EXPOSURE_AUDIT=1 scripts/test-secret-root.sh
scripts/test-secret-postgres.sh
```

The root runner uses a disposable container. Never set its root-test gates when
running test binaries against host `/etc`, `/run` or real account homes. The
runtime DB-client environment is the `isolation-test` target in `Dockerfile`;
its scenarios are in `scripts/test-db-isolation.sh` and `scripts/test-db-supervisor.sh`.

## Coverage limits

The runtime-stage check used host-built Go binaries with the Docker runtime and
test stages. It did not build the original SDK stages or perform an image/SBOM
scan. Outer AppArmor was unconfined for this dedicated check; the host-loaded
AppArmor profile, SELinux and the complete host matrix remain unverified.

Live sshd ingress, MySQL offline secret migration, production-scale interruption
recovery, two-node HA/federation, S3 retention, rolling upgrades and measured
backup/restore RPO/RTO are not covered. Prometheus/Grafana/Collector configurations
are templates without a pinned-distribution deployment test. See
[security limitations](../security/SECURITY_AUDIT.md) for current runtime boundaries.
