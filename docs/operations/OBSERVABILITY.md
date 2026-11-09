# Observability

## Metrics exporter

The exporter in `cmd/observability` is disabled unless `OBS_ENABLED=true`. It binds only to a numeric loopback address, default `127.0.0.1:9090`. `OBS_LISTEN_ADDR` selects another loopback address and port. Configure `OBS_AUTH_TOKEN_FILE` as a root-owned regular file with mode `0400` or `0600`; it must contain at least 32 printable ASCII characters. Do not place the token in an environment variable. `OBS_DB_TIMEOUT` and `OBS_SHUTDOWN_TIMEOUT` accept bounded ranges.

`/metrics`, `/readyz`, `/startupz`, and `/admin/drain` require `Authorization: Bearer <token>`. `/livez` is unauthenticated over loopback. `/admin/drain` and exporter process shutdown mark exporter readiness as draining; they do not stop SSH admission or wait for user sessions. Container shutdown drain behavior is handled separately by `entrypoint.sh` (`DRAIN_TIMEOUT_SECONDS`). Exporter readiness is not SSH readiness or a cluster drain signal.

The exporter provides bounded metric families for registered sessions, event counters, sync duration, and (when configured) pending recording size and age. Session counts are per instance and may include stale registry rows. The sync summary exposes count and sum only. Metrics do not include usernames or session IDs. Event coverage includes session starts, access/authentication/MFA failures, sync results, and local recording publication/archive failures. Exporter-observed database errors are process-local until recovery; realm authentication is reserved without a federation emitter. Broker/jail, migration, and resource instrumentation is incomplete.

## Prometheus and dashboard

The examples in `deploy/observability/` are templates and have not been validated against pinned third-party releases. `prometheus.yml` expects a credentials file containing the raw token and a scrape target in the same host/pod network namespace as goBastion, because the app listener is loopback-only. Reload Prometheus after rotating the token. The dashboard expects datasource UID `DS_PROMETHEUS`. Keep labels bounded; do not add usernames, client addresses, session IDs, key fingerprints, or other sensitive/high-cardinality values. Alert thresholds are examples to tune for the deployment, not availability objectives.

## Tracing and collector

Tracing is optional and disabled unless `OTEL_TRACES_EXPORTER=otlp` is selected. The goBastion runtime rejects nonempty standard OTLP authorization-header variables; configure it to send to a local collector and keep remote credentials and CA configuration in the collector. Numeric loopback HTTP requires `OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK=true`; other endpoints require HTTPS. `OTEL_SDK_DISABLED=true` disables tracing. Instrumentation covers selected startup, authorization/policy, sync, database broker, and recording paths; it is not full request propagation.

The Collector configuration is a template. Validate component names, substitutions, secret mounts, log rotation, redaction, and network access against the pinned Collector build before use. Finite queues can fill and drop telemetry during outages. Telemetry is not an audit-delivery guarantee.
