# Session privilege separation status (G1)

## Status

Partial controls are implemented. The ForceCommand session still has direct
control-plane access; process isolation through a credential broker is not in
place.

## Current behavior

`sshd` invokes a root `sudo` wrapper (`gobastion-session`), which starts
`/app/goBastion` as the connected Unix user. The wrapper copies the root-owned
bootstrap configuration to a mode-0600 temporary file, opens it as descriptor 3,
unlinks the file, and passes the descriptor to the application. Bootstrap
secrets are absent from the Go process's initial environment. The Go process
reads the descriptor, closes it, uses environment variables for legacy
initialization, and unsets secret variables after connecting to the database and
loading the encryption keyring. The session process still retains its DB handle
and key material in memory.

DB client sessions use a distinct privileged supervisor, broker, and NsJail path
(`internal/session/db_supervisor.go`, `internal/dbsandbox`, `cmd/dbworker`).
Direct `--db` ForceCommand requests are routed to that supervisor before the
unprivileged Go session process receives the control-plane bootstrap.
`internal/secretbroker` provides a local Unix-domain socket with peer-UID checks
and an operation allowlist, but ForceCommand session operations do not use it for
database or secret access.

## Security limits

The descriptor transport reduces exposure in the initial process environment;
it does not isolate secrets from code running inside the session process or
prevent that process from querying data allowed by its DB connection. SQLite
file access and the shared control-plane DB remain separate exposure paths.
