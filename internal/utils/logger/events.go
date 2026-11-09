package logger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"goBastion/internal/config"

	"github.com/google/uuid"
)

// EventObserver is implemented by the shared database counter store. The
// logging package does not depend on HTTP or on the database bootstrap layer.
type EventObserver interface {
	Record(context.Context, string, int64) error
	ObserveSyncDuration(context.Context, time.Duration) error
}

type observerState struct{ observer EventObserver }

var currentObserver atomic.Pointer[observerState]
var processRequestID = uuid.NewString()

type traceResolverState struct {
	resolve func(context.Context) (string, string)
}

var traceResolver atomic.Pointer[traceResolverState]

func SetTraceResolver(resolve func(context.Context) (string, string)) {
	if resolve == nil {
		traceResolver.Store(nil)
		return
	}
	traceResolver.Store(&traceResolverState{resolve})
}

// SetEventObserver attaches optional operational counters after DB bootstrap.
// A failed observation never changes the authorization decision.
func SetEventObserver(observer EventObserver) {
	if observer == nil {
		currentObserver.Store(nil)
		return
	}
	currentObserver.Store(&observerState{observer})
}

func sensitiveAttribute(key string) bool {
	switch strings.ToLower(strings.ReplaceAll(key, "-", "_")) {
	case "password", "passwd", "db_dsn", "dsn", "connstring", "connectionstring", "connection_string", "database_url", "database_uri", "credential", "credentials", "secret", "totp_secret", "private_key", "privkey", "privatekey", "key", "api_key", "apikey", "access_token", "refresh_token", "secret_key", "signing_key", "egress_enc_key", "egress_enc_keys", "db_export_key", "recording_signing_key", "authorization", "auth_token", "token", "challenge", "otp", "totp_code", "backup_code", "backup_codes":
		return true
	}
	return false
}

func diagnosticAttribute(key string) bool {
	switch strings.ToLower(key) {
	case "error_text", "error", "err", "exception":
		return true
	}
	return false
}

func safeAttribute(a slog.Attr) slog.Attr {
	if sensitiveAttribute(a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}
	a.Value = a.Value.Resolve()
	// Diagnostic text can contain credentials echoed by an upstream server.
	// Keep the error class; decisions/reasons are separate coded attributes.
	if diagnosticAttribute(a.Key) {
		if err, ok := a.Value.Any().(error); ok {
			return slog.String(a.Key, fmt.Sprintf("%T", err))
		}
		if a.Value.Any() != nil {
			return slog.String(a.Key, "[REDACTED diagnostic]")
		}
	}
	if a.Value.Kind() == slog.KindAny {
		a.Value = slog.AnyValue(safeAnyValue(a.Value.Any(), 0))
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		copyGroup := make([]slog.Attr, len(group))
		for i := range group {
			copyGroup[i] = safeAttribute(group[i])
		}
		a.Value = slog.GroupValue(copyGroup...)
	}
	return a
}

// Never JSON-marshal arbitrary exported fields of errors or client configs.
// Some database errors intentionally redact Error() while retaining the raw
// credential-bearing DSN in an exported field. Maps remain explicitly redacted.
func safeAnyValue(value any, depth int) any {
	if depth > 8 {
		return "[REDACTED nested diagnostic]"
	}
	switch v := value.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v
	case error:
		return fmt.Sprintf("%T", v)
	case uuid.UUID:
		return v.String()
	case []string:
		return append([]string(nil), v...)
	case map[string]any:
		if len(v) > 256 {
			return "[REDACTED oversized diagnostic]"
		}
		out := make(map[string]any, len(v))
		for key, item := range v {
			if sensitiveAttribute(key) {
				out[key] = "[REDACTED]"
			} else if diagnosticAttribute(key) {
				if err, ok := item.(error); ok {
					out[key] = fmt.Sprintf("%T", err)
				} else {
					out[key] = "[REDACTED diagnostic]"
				}
			} else {
				out[key] = safeAnyValue(item, depth+1)
			}
		}
		return out
	case map[string]string:
		if len(v) > 256 {
			return "[REDACTED oversized diagnostic]"
		}
		out := make(map[string]string, len(v))
		for key, item := range v {
			if sensitiveAttribute(key) {
				out[key] = "[REDACTED]"
			} else if diagnosticAttribute(key) {
				out[key] = "[REDACTED diagnostic]"
			} else {
				out[key] = item
			}
		}
		return out
	case []any:
		if len(v) > 256 {
			return "[REDACTED oversized diagnostic]"
		}
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = safeAnyValue(item, depth+1)
		}
		return out
	default:
		return fmt.Sprintf("[REDACTED structured diagnostic %T]", value)
	}
}

func recordAttributes(r slog.Record, pre []slog.Attr) map[string]slog.Value {
	values := make(map[string]slog.Value, len(pre)+r.NumAttrs())
	for _, attr := range pre {
		attr = safeAttribute(attr)
		values[attr.Key] = attr.Value
	}
	r.Attrs(func(a slog.Attr) bool { a = safeAttribute(a); values[a.Key] = a.Value; return true })
	return values
}

func attributeString(attrs map[string]slog.Value, names ...string) string {
	for _, name := range names {
		if value, ok := attrs[name]; ok {
			return value.String()
		}
	}
	return ""
}

// eventFields adds the stable security schema while retaining GELF fields for
// existing consumers. An absent context is represented explicitly as empty.
func eventFields(ctx context.Context, r slog.Record, pre []slog.Attr) map[string]any {
	attrs := recordAttributes(r, pre)
	decision := attributeString(attrs, "decision")
	reason := attributeString(attrs, "reason")
	if decision == "" {
		switch {
		case strings.Contains(r.Message, "denied"), strings.Contains(r.Message, "rejected"), strings.Contains(r.Message, "failure"), reason == "access_denied":
			decision = "deny"
		case r.Level >= slog.LevelError:
			decision = "error"
		default:
			decision = "observe"
		}
	}
	sessionID := attributeString(attrs, "session_id")
	if sessionID == "" {
		sessionID = os.Getenv("GOB_SESSION_ID")
	}
	requestID := attributeString(attrs, "request_id")
	if requestID == "" {
		requestID = processRequestID
	}
	eventID := attributeString(attrs, "event_id")
	if eventID == "" {
		eventID = uuid.NewString()
	}
	protocol := attributeString(attrs, "protocol")
	if protocol == "" {
		switch {
		case strings.HasPrefix(r.Message, "ssh_"):
			protocol = "ssh"
		case strings.HasPrefix(r.Message, "sftp_"):
			protocol = "sftp"
		case strings.HasPrefix(r.Message, "db_session"):
			protocol = "database"
		}
	}
	duration := float64(0)
	for _, name := range []string{"duration", "took"} {
		if v, ok := attrs[name]; ok && v.Kind() == slog.KindDuration {
			duration = float64(v.Duration()) / float64(time.Millisecond)
			break
		}
	}
	fields := map[string]any{
		"event_id":    eventID,
		"event_type":  r.Message,
		"instance_id": config.InstanceID(),
		"request_id":  requestID,
		"action":      r.Message,
		"decision":    decision,
	}
	if sessionID != "" {
		fields["session_id"] = sessionID
	}
	if actor := attributeString(attrs, "actor", "user"); actor != "" {
		fields["actor"] = actor
	}
	if sourceIP := attributeString(attrs, "source_ip", "from", "ip", "client_ip"); sourceIP != "" {
		fields["source_ip"] = sourceIP
	}
	if target := attributeString(attrs, "target", "to", "server"); target != "" {
		fields["target"] = target
	}
	if protocol != "" {
		fields["protocol"] = protocol
	}
	if reason != "" {
		fields["reason"] = reason
	}
	if duration > 0 {
		fields["duration_ms"] = duration
	}
	if action := attributeString(attrs, "action"); action != "" {
		fields["action"] = action
	}
	if resolver := traceResolver.Load(); resolver != nil {
		if traceID, spanID := resolver.resolve(ctx); traceID != "" {
			fields["trace_id"] = traceID
			fields["span_id"] = spanID
		}
	}
	return fields
}

func observeEvent(ctx context.Context, r slog.Record, pre []slog.Attr) error {
	state := currentObserver.Load()
	if state == nil {
		return nil
	}
	attrs := recordAttributes(r, pre)
	metric := ""
	switch r.Message {
	case "session_start", "db_session_start":
		metric = "gobastion_sessions_total"
	case "login_rejected", "authentication_failed":
		metric = "gobastion_auth_failures_total"
	case "mfa_failure":
		metric = "gobastion_mfa_failures_total"
	// session_admission_denied is the caller's summary of the same decision
	// recorded by authorization_result below; counting both would double it.
	case "access_denied":
		metric = "gobastion_access_denied_total"
	case "db_connection_failed":
		metric = "gobastion_db_connection_errors_total"
	case "recording_archival_failed", "db_recording_retained", "ssh_recording_retained", "recording_recovery_failed":
		metric = "gobastion_recording_archival_failures_total"
	case "realm_authentication_failed":
		metric = "gobastion_realm_auth_failures_total"
	}
	if attributeString(attrs, "reason") == "access_denied" {
		metric = "gobastion_access_denied_total"
	}
	if r.Message == "authorization_result" && attributeString(attrs, "decision") == "deny" {
		metric = "gobastion_access_denied_total"
	}
	if metric == "" && r.Message != "sync_result" {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	if metric != "" {
		return state.observer.Record(bounded, metric, 1)
	}
	if duration, ok := attrs["duration"]; ok && duration.Kind() == slog.KindDuration {
		var result error
		if success, ok := attrs["success"]; ok && success.Kind() == slog.KindBool && !success.Bool() {
			result = state.observer.Record(bounded, "gobastion_sync_failures_total", 1)
		}
		return errors.Join(result, state.observer.ObserveSyncDuration(bounded, duration.Duration()))
	}
	return nil
}
