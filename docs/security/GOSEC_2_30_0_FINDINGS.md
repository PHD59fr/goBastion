# Gosec findings

Recorded scan: Gosec 2.30.0, 2026-11-10, `-concurrency=2 -nosec=true -fmt=sarif ./...`.
The scan exits 1 with 84 findings (38 HIGH, 46 MEDIUM scanner labels), with
no load errors or nosec exclusions. The baseline comparison checks rule ID,
source path, message and occurrence count against this inventory; line numbers
are informational. Reviewed findings remain visible in the scanner report.

The [source analysis](SCANNER_TRIAGE.md) explains reviewed paths. The inventory
omits source snippets and credential values; findings without an accepted review
remain open.

| Rule | Scanner severity | Confidence | Source | Scanner description | Review status |
| --- | --- | --- | --- | --- | --- |
| G302 | MEDIUM | HIGH | [internal/secretbroker/broker.go:107](../../internal/secretbroker/broker.go#L107) | Expect file permissions to be 0600 or less | Reviewed: intentional owner/group access to a Unix socket; protected directory, peer credentials and operation allowlist. See SCANNER_TRIAGE.md. |
| G302 | MEDIUM | HIGH | [internal/startup/recording_autofix.go:32](../../internal/startup/recording_autofix.go#L32) | Expect file permissions to be 0600 or less | Reviewed: root-only recording migration backup directory requires owner execute/traverse permission (`0700`); it must remain inaccessible to non-root users. |
| G115 | HIGH | MEDIUM | [internal/dbsandbox/terminal.go:128](../../internal/dbsandbox/terminal.go#L128) | integer overflow conversion uintptr -> int32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/utils/totp/totp.go:41](../../internal/utils/totp/totp.go#L41) | integer overflow conversion int64 -> uint64 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/archive/types.go:271](../../internal/recording/archive/types.go#L271) | integer overflow conversion int -> uint64 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/archive/types.go:271](../../internal/recording/archive/types.go#L271) | integer overflow conversion int -> uint64 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/utils/sync/secure_ssh.go:147](../../internal/utils/sync/secure_ssh.go#L147) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/utils/sync/secure_ssh.go:147](../../internal/utils/sync/secure_ssh.go#L147) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/utils/sync/secure_ssh.go:130](../../internal/utils/sync/secure_ssh.go#L130) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/utils/sync/secure_ssh.go:112](../../internal/utils/sync/secure_ssh.go#L112) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/ssh_spool.go:59](../../internal/recording/ssh_spool.go#L59) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/retire.go:388](../../internal/recording/retire.go#L388) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/retire.go:251](../../internal/recording/retire.go#L251) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/retire.go:63](../../internal/recording/retire.go#L63) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/retire.go:63](../../internal/recording/retire.go#L63) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/directories.go:184](../../internal/recording/directories.go#L184) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/directories.go:184](../../internal/recording/directories.go#L184) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/directories.go:95](../../internal/recording/directories.go#L95) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/directories.go:88](../../internal/recording/directories.go#L88) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/directories.go:63](../../internal/recording/directories.go#L63) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/archive/writer.go:239](../../internal/recording/archive/writer.go#L239) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/archive/writer.go:182](../../internal/recording/archive/writer.go#L182) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/archive/writer.go:108](../../internal/recording/archive/writer.go#L108) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/recording/archive/reader.go:197](../../internal/recording/archive/reader.go#L197) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/dbsandbox/broker_postgres.go:169](../../internal/dbsandbox/broker_postgres.go#L169) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [cmd/recording-admin/main.go:451](../../cmd/recording-admin/main.go#L451) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [cmd/recording-admin/main.go:231](../../cmd/recording-admin/main.go#L231) | integer overflow conversion int -> uint32 | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/dbsandbox/broker_mysql.go:198](../../internal/dbsandbox/broker_mysql.go#L198) | integer overflow conversion int -> byte | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/dbsandbox/broker_mysql.go:198](../../internal/dbsandbox/broker_mysql.go#L198) | integer overflow conversion int -> byte | Pending individual review |
| G115 | HIGH | MEDIUM | [internal/dbsandbox/broker_mysql.go:198](../../internal/dbsandbox/broker_mysql.go#L198) | integer overflow conversion int -> byte | Pending individual review |
| G407 | HIGH | HIGH | [internal/recording/archive/writer.go:183](../../internal/recording/archive/writer.go#L183) | Use of hardcoded IV/nonce for encryption by passing hardcoded constant | Pending individual review |
| G101 | HIGH | LOW | [internal/commands/account/info.go:84](../../internal/commands/account/info.go#L84) | Potential hardcoded credentials | Pending individual review |
| G703 | HIGH | HIGH | [internal/utils/sshConnector/sshConnector.go:220](../../internal/utils/sshConnector/sshConnector.go#L220) | Path traversal via taint analysis: os.Stat | Pending individual review |
| G703 | HIGH | HIGH | [internal/utils/dbConnector/dbConnector.go:198](../../internal/utils/dbConnector/dbConnector.go#L198) | Path traversal via taint analysis: os.Stat | Pending individual review |
| G703 | HIGH | HIGH | [internal/observability/config.go:116](../../internal/observability/config.go#L116) | Path traversal via taint analysis: os.OpenFile | Pending individual review |
| G703 | HIGH | HIGH | [cmd/recording-admin/main.go:207](../../cmd/recording-admin/main.go#L207) | Path traversal via taint analysis: os.OpenFile | Pending individual review |
| G703 | HIGH | HIGH | [internal/utils/sshConnector/sshConnector.go:262](../../internal/utils/sshConnector/sshConnector.go#L262) | Path traversal via taint analysis: os.Open | Pending individual review |
| G703 | HIGH | HIGH | [internal/utils/dbConnector/dbConnector.go:235](../../internal/utils/dbConnector/dbConnector.go#L235) | Path traversal via taint analysis: os.Open | Pending individual review |
| G702 | HIGH | HIGH | [internal/utils/sshConnector/sshConnector.go:321](../../internal/utils/sshConnector/sshConnector.go#L321) | Command injection via taint analysis: os/exec.CommandContext | Pending individual review |
| G702 | HIGH | HIGH | [internal/utils/dbConnector/dbConnector.go:291](../../internal/utils/dbConnector/dbConnector.go#L291) | Command injection via taint analysis: os/exec.CommandContext | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/utils/sshConnector/sshConnector.go:421](../../internal/utils/sshConnector/sshConnector.go#L421) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/utils/sshConnector/sshConnector.go:163](../../internal/utils/sshConnector/sshConnector.go#L163) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/utils/sshConnector/sshConnector.go:144](../../internal/utils/sshConnector/sshConnector.go#L144) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/utils/dbConnector/dbConnector.go:291](../../internal/utils/dbConnector/dbConnector.go#L291) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/osadapter/linux.go:225](../../internal/osadapter/linux.go#L225) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:149](../../internal/dbsandbox/sandbox.go#L149) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/commands/tty/play.go:113](../../internal/commands/tty/play.go#L113) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/commands/self/generate_egress_key.go:93](../../internal/commands/self/generate_egress_key.go#L93) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/commands/group/generate_egress_key.go:96](../../internal/commands/group/generate_egress_key.go#L96) | Subprocess launched with variable | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/utils/sshConnector/sshConnector.go:321](../../internal/utils/sshConnector/sshConnector.go#L321) | Subprocess launched with a potential tainted input or cmd arguments | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/osadapter/linux.go:204](../../internal/osadapter/linux.go#L204) | Subprocess launched with a potential tainted input or cmd arguments | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:303](../../internal/dbsandbox/sandbox.go#L303) | Subprocess launched with a potential tainted input or cmd arguments | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:214](../../internal/dbsandbox/sandbox.go#L214) | Subprocess launched with a potential tainted input or cmd arguments | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:165](../../internal/dbsandbox/sandbox.go#L165) | Subprocess launched with a potential tainted input or cmd arguments | Pending individual review |
| G204 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:153](../../internal/dbsandbox/sandbox.go#L153) | Subprocess launched with a potential tainted input or cmd arguments | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/sync/sync.go:415](../../internal/utils/sync/sync.go#L415) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/sync/auditors.go:328](../../internal/utils/sync/auditors.go#L328) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/sshHostKey/sshHostKey.go:161](../../internal/utils/sshHostKey/sshHostKey.go#L161) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/sshHostKey/sshHostKey.go:157](../../internal/utils/sshHostKey/sshHostKey.go#L157) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/sshConnector/sshConnector.go:262](../../internal/utils/sshConnector/sshConnector.go#L262) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/dbConnector/dbConnector.go:235](../../internal/utils/dbConnector/dbConnector.go#L235) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/cryptokey/cryptokey.go:368](../../internal/utils/cryptokey/cryptokey.go#L368) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/utils/cryptokey/cryptokey.go:329](../../internal/utils/cryptokey/cryptokey.go#L329) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/recording/spool.go:47](../../internal/recording/spool.go#L47) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/recording/spool.go:39](../../internal/recording/spool.go#L39) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/recording/spool.go:25](../../internal/recording/spool.go#L25) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/recording/publish.go:90](../../internal/recording/publish.go#L90) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/observability/config.go:116](../../internal/observability/config.go#L116) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/commands/self/generate_egress_key.go:117](../../internal/commands/self/generate_egress_key.go#L117) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/commands/self/generate_egress_key.go:106](../../internal/commands/self/generate_egress_key.go#L106) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/commands/self/add_ingress_key_piv.go:92](../../internal/commands/self/add_ingress_key_piv.go#L92) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/commands/self/add_ingress_key_piv.go:82](../../internal/commands/self/add_ingress_key_piv.go#L82) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/commands/piv/add_trust_anchor.go:44](../../internal/commands/piv/add_trust_anchor.go#L44) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/commands/group/generate_egress_key.go:104](../../internal/commands/group/generate_egress_key.go#L104) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [internal/commands/group/generate_egress_key.go:103](../../internal/commands/group/generate_egress_key.go#L103) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [cmd/secret-migrate/main.go:106](../../cmd/secret-migrate/main.go#L106) | Potential file inclusion via variable | Pending individual review |
| G304 | MEDIUM | HIGH | [cmd/recording-admin/main.go:207](../../cmd/recording-admin/main.go#L207) | Potential file inclusion via variable | Pending individual review |
| G302 | MEDIUM | HIGH | [internal/utils/logger/logger.go:330](../../internal/utils/logger/logger.go#L330) | Expect file permissions to be 0600 or less | Pending individual review |
| G302 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:123](../../internal/dbsandbox/sandbox.go#L123) | Expect file permissions to be 0600 or less | Pending individual review |
| G302 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:108](../../internal/dbsandbox/sandbox.go#L108) | Expect file permissions to be 0600 or less | Pending individual review |
| G302 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:44](../../internal/dbsandbox/sandbox.go#L44) | Expect file permissions to be 0600 or less | Pending individual review |
| G302 | MEDIUM | HIGH | [internal/db/db.go:218](../../internal/db/db.go#L218) | Expect file permissions to be 0600 or less | Pending individual review |
| G301 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:41](../../internal/dbsandbox/sandbox.go#L41) | Expect directory permissions to be 0750 or less | Pending individual review |
| G306 | MEDIUM | HIGH | [internal/dbsandbox/sandbox.go:104](../../internal/dbsandbox/sandbox.go#L104) | Expect WriteFile permissions to be 0600 or less | Pending individual review |
| G505 | MEDIUM | HIGH | [internal/utils/totp/totp.go:6](../../internal/utils/totp/totp.go#L6) | Blocklisted import crypto/sha1: weak cryptographic primitive | Pending individual review |
