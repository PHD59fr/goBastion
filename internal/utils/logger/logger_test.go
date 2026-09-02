package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newTestJSONHandler returns a jsonHandler writing to a buffer for testing.
func newTestJSONHandler(buf *bytes.Buffer) *jsonHandler {
	h := newJSONHandler(buf)
	h.host = "testhost"
	return h
}

// decodeJSON parses a single JSON log line.
func decodeJSON(t *testing.T, data string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &m); err != nil {
		t.Fatalf("failed to decode JSON: %v\nraw: %s", err, data)
	}
	return m
}

func TestJSONHandler_BasicRecord(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "hello world", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeJSON(t, buf.String())

	if m["version"] != "1.1" {
		t.Errorf("expected version=1.1, got %v", m["version"])
	}
	if m["host"] != "testhost" {
		t.Errorf("expected host=testhost, got %v", m["host"])
	}
	if m["short_message"] != "hello world" {
		t.Errorf("expected short_message=hello world, got %v", m["short_message"])
	}
	if m["msg"] != "hello world" {
		t.Errorf("expected msg=hello world, got %v", m["msg"])
	}
	if _, ok := m["timestamp"]; !ok {
		t.Error("expected timestamp field")
	}
	if _, ok := m["time"]; !ok {
		t.Error("expected time field")
	}
}

func TestJSONHandler_Levels(t *testing.T) {
	cases := []struct {
		slogLevel slog.Level
		want      int
	}{
		{slog.LevelDebug, 7},
		{slog.LevelInfo, 6},
		{slog.LevelWarn, 4},
		{slog.LevelError, 3},
	}

	for _, tc := range cases {
		t.Run(tc.slogLevel.String(), func(t *testing.T) {
			var buf bytes.Buffer
			h := newTestJSONHandler(&buf)
			h.min = slog.LevelDebug

			r := slog.NewRecord(time.Now(), tc.slogLevel, "msg", 0)
			if err := h.Handle(context.Background(), r); err != nil {
				t.Fatalf("Handle error: %v", err)
			}

			m := decodeJSON(t, buf.String())
			if int(m["level"].(float64)) != tc.want {
				t.Errorf("level %s: expected gelf level %d, got %v", tc.slogLevel, tc.want, m["level"])
			}
		})
	}
}

func TestJSONHandler_Attrs(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	r.AddAttrs(slog.String("user", "phd"), slog.String("ip", "1.2.3.4"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeJSON(t, buf.String())
	if m["_user"] != "phd" {
		t.Errorf("expected _user=phd, got %v", m["_user"])
	}
	if m["_ip"] != "1.2.3.4" {
		t.Errorf("expected _ip=1.2.3.4, got %v", m["_ip"])
	}
}

func TestJSONHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)

	child := h.WithAttrs([]slog.Attr{slog.String("user", "phd")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "command", 0)
	r.AddAttrs(slog.String("cmd", "selfListIngressKeys"))
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeJSON(t, buf.String())
	if m["_user"] != "phd" {
		t.Errorf("WithAttrs: expected _user=phd, got %v", m["_user"])
	}
	if m["_cmd"] != "selfListIngressKeys" {
		t.Errorf("WithAttrs: expected _cmd, got %v", m["_cmd"])
	}
}

func TestJSONHandler_WithAttrs_RecordWins(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)
	child := h.WithAttrs([]slog.Attr{slog.String("user", "original")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "override", 0)
	r.AddAttrs(slog.String("user", "overridden"))
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeJSON(t, buf.String())
	if m["_user"] != "overridden" {
		t.Errorf("expected record attr to win over pre-attr, got %v", m["_user"])
	}
}

func TestJSONHandler_WithAttrs_Chaining(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)

	child := h.WithAttrs([]slog.Attr{slog.String("service", "goBastion")}).
		WithAttrs([]slog.Attr{slog.String("user", "phd")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "chained", 0)
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeJSON(t, buf.String())
	if m["_service"] != "goBastion" {
		t.Errorf("expected _service=goBastion, got %v", m["_service"])
	}
	if m["_user"] != "phd" {
		t.Errorf("expected _user=phd, got %v", m["_user"])
	}
}

func TestJSONHandler_Enabled(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be disabled at Info level")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info to be enabled")
	}
}

func TestMultiHandler_FansOut(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := newTestJSONHandler(&buf1)
	h2 := newTestJSONHandler(&buf2)
	multi := &multiHandler{handlers: []slog.Handler{h1, h2}}

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "fanout", 0)
	if err := multi.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	if buf1.Len() == 0 {
		t.Error("expected handler1 to receive the record")
	}
	if buf2.Len() == 0 {
		t.Error("expected handler2 to receive the record")
	}

	m1 := decodeJSON(t, buf1.String())
	m2 := decodeJSON(t, buf2.String())
	if m1["short_message"] != "fanout" || m2["short_message"] != "fanout" {
		t.Errorf("unexpected messages: %v / %v", m1["short_message"], m2["short_message"])
	}
}

func TestMultiHandler_WithAttrs_Propagates(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)
	multi := &multiHandler{handlers: []slog.Handler{h}}

	child := multi.WithAttrs([]slog.Attr{slog.String("user", "phd")})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "prop", 0)
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeJSON(t, buf.String())
	if m["_user"] != "phd" {
		t.Errorf("multiHandler.WithAttrs should propagate to child handlers, got %v", m["_user"])
	}
}

func TestSlogLevelToGelf(t *testing.T) {
	cases := []struct {
		in   slog.Level
		want int
	}{
		{slog.LevelDebug, 7},
		{slog.LevelInfo, 6},
		{slog.LevelWarn, 4},
		{slog.LevelError, 3},
		{slog.LevelError + 4, 3},
	}
	for _, tc := range cases {
		if got := slogLevelToGelf(tc.in); got != tc.want {
			t.Errorf("slogLevelToGelf(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestPlainTextHandlerSanitizesControls(t *testing.T) {
	var buf bytes.Buffer
	h := newPlainTextHandler(&buf)
	r := slog.NewRecord(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), slog.LevelInfo, "msg\r\n\x1b\x00\u0085\x7f", 0)
	r.AddAttrs(slog.String("ke\ty", "value\b\f\u009f"))

	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	got := buf.String()
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("plain output contains an injected line break: %q", got)
	}
	for _, want := range []string{
		`msg\u000d\u000a\u001b\u0000\u0085\u007f`,
		`ke\u0009y=value\u0008\u000c\u009f`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plain output %q does not contain %q", got, want)
		}
	}
	assertNoLogControls(t, got[:len(got)-1])
}

type testSyslogWriter struct {
	severity string
	message  string
}

func (w *testSyslogWriter) Err(message string) error {
	w.severity, w.message = "error", message
	return nil
}

func (w *testSyslogWriter) Warning(message string) error {
	w.severity, w.message = "warning", message
	return nil
}

func (w *testSyslogWriter) Info(message string) error {
	w.severity, w.message = "info", message
	return nil
}

func TestSyslogHandlerSanitizesControls(t *testing.T) {
	w := &testSyslogWriter{}
	h := &syslogHandler{writer: w, level: slog.LevelInfo}
	r := slog.NewRecord(time.Now(), slog.LevelWarn, "msg\n\x1b\u0080", 0)
	r.AddAttrs(slog.String("ke\ry", "value\x00\x7f\u009f"))

	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	if w.severity != "warning" {
		t.Errorf("severity = %q, want warning", w.severity)
	}
	want := `msg\u000a\u001b\u0080 ke\u000dy=value\u0000\u007f\u009f`
	if w.message != want {
		t.Errorf("syslog message = %q, want %q", w.message, want)
	}
	assertNoLogControls(t, w.message)
}

func TestJSONHandlerPreservesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	h := newTestJSONHandler(&buf)
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "msg\n\x1b\u0085", 0)
	r.AddAttrs(slog.String("ke\ry", "value\x00\x7f\u009f"))

	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeJSON(t, buf.String())
	if m["msg"] != "msg\n\x1b\u0085" {
		t.Errorf("JSON message was sanitized instead of JSON-escaped: %q", m["msg"])
	}
	if m["_ke\ry"] != "value\x00\x7f\u009f" {
		t.Errorf("JSON attribute was sanitized instead of JSON-escaped: %q", m["_ke\ry"])
	}
}

func assertNoLogControls(t *testing.T, value string) {
	t.Helper()
	for _, r := range value {
		if (r >= 0 && r <= 0x1f) || (r >= 0x7f && r <= 0x9f) {
			t.Errorf("output contains control character U+%04X: %q", r, value)
		}
	}
}
