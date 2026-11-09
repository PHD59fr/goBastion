package logger

import (
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSecurityEventSchemaAndSecretRedaction(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(newJSONHandler(&output)).With("user", "alice", "password", "never-log-this")
	log.Warn("ssh_connect", "reason", "access_denied", "to", "fixture", "private_key", "never-log-key", "duration", 15*time.Millisecond)
	value := decodeJSON(t, output.String())
	for _, field := range []string{"timestamp", "event_id", "event_type", "instance_id", "session_id", "request_id", "actor", "source_ip", "target", "protocol", "action", "decision", "reason", "duration_ms"} {
		if _, ok := value[field]; !ok {
			t.Fatalf("missing event field %s", field)
		}
	}
	if value["actor"] != "alice" || value["decision"] != "deny" || value["target"] != "fixture" || value["protocol"] != "ssh" || value["duration_ms"] != float64(15) {
		t.Fatal("incorrect security event context")
	}
	if strings.Contains(output.String(), "never-log") {
		t.Fatal("secret attribute reached log output")
	}
}

func TestStructuredDatabaseErrorCannotMarshalItsRawDSN(t *testing.T) {
	const marker = "credential-that-must-not-enter-structured-logs"
	_, parseErr := pgconn.ParseConfig("host=fixture user=operator password=" + marker + " connect_timeout=invalid")
	if parseErr == nil {
		t.Fatal("bad database fixture did not produce a parser error")
	}
	var output bytes.Buffer
	slog.New(newJSONHandler(&output)).Error("db_connection_failed", "error", parseErr, "details", map[string]any{"nested": map[string]any{"password": marker, "error": parseErr}})
	if strings.Contains(output.String(), marker) {
		t.Fatal("structured error serialization exposed a raw credential")
	}
	value := decodeJSON(t, output.String())
	if _, ok := value["_error"].(string); !ok {
		t.Fatal("error was serialized as an arbitrary object")
	}
}

func TestUntrustedErrorMessagesAreNotExported(t *testing.T) {
	var output bytes.Buffer
	slog.New(newJSONHandler(&output)).Error("upstream_failure", "error", errors.New("upstream echoed a credential-marker"), "error_text", "credential-marker", "nested", map[string]any{
		"failure": errors.New("credential-marker"),
		"details": map[string]any{"error_text": "credential-marker", "ERROR": "credential-marker"},
		"strings": map[string]string{"exception": "credential-marker", "err": "credential-marker"},
	})
	if strings.Contains(output.String(), "credential-marker") {
		t.Fatal("untrusted diagnostic message reached audit logs")
	}
}

func TestConcurrentDerivedLoggersShareOutputLock(t *testing.T) {
	for _, format := range []string{"json", "plain"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			var handler slog.Handler = newJSONHandler(&output)
			if format == "plain" {
				handler = newPlainTextHandler(&output)
			}
			root := slog.New(handler)
			var writers sync.WaitGroup
			for i := 0; i < 12; i++ {
				log := root.With("worker", i)
				writers.Go(func() {
					for j := 0; j < 30; j++ {
						log.Info("concurrent_event")
					}
				})
			}
			writers.Wait()
			if strings.Count(output.String(), "\n") != 360 {
				t.Fatal("concurrent log records were lost or interleaved")
			}
			if format == "json" {
				seen := map[string]bool{}
				for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
					value := decodeJSON(t, line)
					id := value["event_id"].(string)
					if id == "" || seen[id] {
						t.Fatal("event id was reused")
					}
					seen[id] = true
				}
			}
		})
	}
}

type testObserver struct {
	metric   string
	count    int64
	duration time.Duration
	fail     bool
}

func (o *testObserver) Record(_ context.Context, name string, delta int64) error {
	o.metric = name
	o.count += delta
	if o.fail {
		return errors.New("credential must not be printed")
	}
	return nil
}
func (o *testObserver) ObserveSyncDuration(_ context.Context, d time.Duration) error {
	o.duration = d
	return nil
}

func TestCountersObservedOnceAndFailuresDoNotDropAudit(t *testing.T) {
	observer := &testObserver{}
	SetEventObserver(observer)
	t.Cleanup(func() { SetEventObserver(nil) })
	var first, second bytes.Buffer
	log := slog.New(&multiHandler{handlers: []slog.Handler{newJSONHandler(&first), newPlainTextHandler(&second)}}).With("reason", "access_denied")
	log.Warn("ssh_connect")
	if observer.metric != "gobastion_access_denied_total" || observer.count != 1 {
		t.Fatal("counter fanout duplicated or omitted observation")
	}
	observer.fail = true
	log.Warn("ssh_connect")
	if !strings.Contains(first.String(), "observability_counter_update_failed") || !strings.Contains(first.String(), "ssh_connect") {
		t.Fatal("counter failure dropped audit or lacked loss indication")
	}
	if strings.Contains(first.String(), "credential must not") {
		t.Fatal("counter backend diagnostic leaked to logs")
	}
}

func TestAdmissionDenialSummaryDoesNotCountAsSecondDecision(t *testing.T) {
	observer := &testObserver{}
	SetEventObserver(observer)
	t.Cleanup(func() { SetEventObserver(nil) })
	log := slog.New(&multiHandler{handlers: []slog.Handler{newJSONHandler(&bytes.Buffer{})}})
	log.Info("authorization_result", "decision", "deny")
	log.Warn("session_admission_denied", "error", errors.New("denied"))
	if observer.metric != "gobastion_access_denied_total" || observer.count != 1 {
		t.Fatalf("admission denial observations = %d for %q, want one access denial", observer.count, observer.metric)
	}
	log.Warn("ssh_connect", "reason", "access_denied")
	if observer.count != 2 {
		t.Fatalf("target access denial was not counted: got %d", observer.count)
	}
}

func TestSyslogAndJSONShareEventIdentityAndRedaction(t *testing.T) {
	var output bytes.Buffer
	remote := &testSyslogWriter{}
	log := slog.New(&multiHandler{handlers: []slog.Handler{newJSONHandler(&output), &syslogHandler{writer: remote, level: slog.LevelInfo}}}).With("user", "fixture", "secret", "never-export-this")
	log.Info("session_start")
	local := decodeJSON(t, output.String())
	exported := decodeJSON(t, remote.message)
	if local["event_id"] != exported["event_id"] || local["actor"] != exported["actor"] {
		t.Fatal("audit export lost event correlation")
	}
	if strings.Contains(remote.message, "never-export-this") {
		t.Fatal("secret reached syslog")
	}
}
