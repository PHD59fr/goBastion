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

// newTestGelfHandler returns a gelfHandler writing to a buffer for testing.
func newTestGelfHandler(buf *bytes.Buffer) *gelfHandler {
	h := newGelfHandler(buf)
	h.host = "testhost"
	return h
}

// decodeGELF parses a single GELF JSON line.
func decodeGELF(t *testing.T, data string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &m); err != nil {
		t.Fatalf("failed to decode GELF JSON: %v\nraw: %s", err, data)
	}
	return m
}

func TestGelfHandler_BasicRecord(t *testing.T) {
	var buf bytes.Buffer
	h := newTestGelfHandler(&buf)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "hello world", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeGELF(t, buf.String())

	if m["version"] != "1.1" {
		t.Errorf("expected version=1.1, got %v", m["version"])
	}
	if m["host"] != "testhost" {
		t.Errorf("expected host=testhost, got %v", m["host"])
	}
	if m["short_message"] != "hello world" {
		t.Errorf("expected short_message=hello world, got %v", m["short_message"])
	}
	if int(m["level"].(float64)) != gelfLevelInfo {
		t.Errorf("expected level=%d (info), got %v", gelfLevelInfo, m["level"])
	}
}

func TestGelfHandler_Levels(t *testing.T) {
	cases := []struct {
		slogLevel slog.Level
		want      int
	}{
		{slog.LevelDebug, gelfLevelDebug},
		{slog.LevelInfo, gelfLevelInfo},
		{slog.LevelWarn, gelfLevelWarning},
		{slog.LevelError, gelfLevelError},
	}

	for _, tc := range cases {
		t.Run(tc.slogLevel.String(), func(t *testing.T) {
			var buf bytes.Buffer
			h := newTestGelfHandler(&buf)
			h.min = slog.LevelDebug // allow all levels

			r := slog.NewRecord(time.Now(), tc.slogLevel, "msg", 0)
			if err := h.Handle(context.Background(), r); err != nil {
				t.Fatalf("Handle error: %v", err)
			}

			m := decodeGELF(t, buf.String())
			if int(m["level"].(float64)) != tc.want {
				t.Errorf("level %s: expected gelf level %d, got %v", tc.slogLevel, tc.want, m["level"])
			}
		})
	}
}

func TestGelfHandler_Attrs(t *testing.T) {
	var buf bytes.Buffer
	h := newTestGelfHandler(&buf)

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	r.AddAttrs(slog.String("user", "phd"), slog.String("ip", "1.2.3.4"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeGELF(t, buf.String())
	if m["_user"] != "phd" {
		t.Errorf("expected _user=phd, got %v", m["_user"])
	}
	if m["_ip"] != "1.2.3.4" {
		t.Errorf("expected _ip=1.2.3.4, got %v", m["_ip"])
	}
}

// TestGelfHandler_WithAttrs is a regression test for the bug where WithAttrs
// returned the same handler ignoring the attributes entirely.
func TestGelfHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := newTestGelfHandler(&buf)

	// Simulate log.With("user", "phd")
	child := h.WithAttrs([]slog.Attr{slog.String("user", "phd")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "command", 0)
	r.AddAttrs(slog.String("cmd", "selfListIngressKeys"))
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeGELF(t, buf.String())

	if m["_user"] != "phd" {
		t.Errorf("WithAttrs: expected _user=phd in output, got %v — WithAttrs may not be storing pre-attrs", m["_user"])
	}
	if m["_cmd"] != "selfListIngressKeys" {
		t.Errorf("WithAttrs: expected _cmd in output, got %v", m["_cmd"])
	}
}

// TestGelfHandler_WithAttrs_RecordWins verifies that per-record attrs
// override pre-attrs on key collision.
func TestGelfHandler_WithAttrs_RecordWins(t *testing.T) {
	var buf bytes.Buffer
	h := newTestGelfHandler(&buf)
	child := h.WithAttrs([]slog.Attr{slog.String("user", "original")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "override", 0)
	r.AddAttrs(slog.String("user", "overridden"))
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeGELF(t, buf.String())
	if m["_user"] != "overridden" {
		t.Errorf("expected record attr to win over pre-attr, got %v", m["_user"])
	}
}

func TestGelfHandler_WithAttrs_Chaining(t *testing.T) {
	var buf bytes.Buffer
	h := newTestGelfHandler(&buf)

	// Chain two WithAttrs calls.
	child := h.WithAttrs([]slog.Attr{slog.String("service", "goBastion")}).
		WithAttrs([]slog.Attr{slog.String("user", "phd")})

	r := slog.NewRecord(time.Now(), slog.LevelInfo, "chained", 0)
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeGELF(t, buf.String())
	if m["_service"] != "goBastion" {
		t.Errorf("expected _service=goBastion, got %v", m["_service"])
	}
	if m["_user"] != "phd" {
		t.Errorf("expected _user=phd, got %v", m["_user"])
	}
}

func TestGelfHandler_Enabled(t *testing.T) {
	var buf bytes.Buffer
	h := newTestGelfHandler(&buf)
	// Default min = Info: debug should not be enabled.
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be disabled at Info level")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info to be enabled")
	}
}

func TestMultiHandler_FansOut(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := newTestGelfHandler(&buf1)
	h2 := newTestGelfHandler(&buf2)
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

	m1 := decodeGELF(t, buf1.String())
	m2 := decodeGELF(t, buf2.String())
	if m1["short_message"] != "fanout" || m2["short_message"] != "fanout" {
		t.Errorf("unexpected messages: %v / %v", m1["short_message"], m2["short_message"])
	}
}

func TestMultiHandler_WithAttrs_Propagates(t *testing.T) {
	var buf bytes.Buffer
	h := newTestGelfHandler(&buf)
	multi := &multiHandler{handlers: []slog.Handler{h}}

	child := multi.WithAttrs([]slog.Attr{slog.String("user", "phd")})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "prop", 0)
	if err := child.Handle(context.Background(), r); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := decodeGELF(t, buf.String())
	if m["_user"] != "phd" {
		t.Errorf("multiHandler.WithAttrs should propagate to child handlers, got %v", m["_user"])
	}
}

func TestSlogLevelToGelf(t *testing.T) {
	cases := []struct {
		in   slog.Level
		want int
	}{
		{slog.LevelDebug, gelfLevelDebug},
		{slog.LevelInfo, gelfLevelInfo},
		{slog.LevelInfo + 1, gelfLevelInfo},
		{slog.LevelWarn, gelfLevelWarning},
		{slog.LevelError, gelfLevelError},
		{slog.LevelError + 4, gelfLevelError},
	}
	for _, tc := range cases {
		if got := slogLevelToGelf(tc.in); got != tc.want {
			t.Errorf("slogLevelToGelf(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
