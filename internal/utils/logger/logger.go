package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"log/syslog"
	"os"
	"strings"
	"sync"
)

const logFile = "/goBastion.log"

// slogLevelToGelf maps a slog level to a GELF syslog severity number.
func slogLevelToGelf(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return 3
	case l >= slog.LevelWarn:
		return 4
	case l >= slog.LevelInfo:
		return 6
	default:
		return 7
	}
}

// jsonHandler writes structured JSON records to an io.Writer.
// Each record is a single line of JSON.
//
// Fields produced (GELF 1.1 + human-readable):
//
//	version       "1.1"
//	host          container hostname
//	short_message log message
//	timestamp     unix float64
//	level         syslog numeric level (0-7)
//	msg           log message (duplicate of short_message for readability)
//	time          ISO 8601 timestamp
//	_<key>        all additional slog attributes prefixed with _
type jsonHandler struct {
	mu       sync.Mutex
	w        io.Writer
	host     string
	min      slog.Level
	preAttrs []slog.Attr // stored via WithAttrs (e.g. log.With("user", ...))
}

// newJSONHandler creates a new structured JSON log handler writing to w.
func newJSONHandler(w io.Writer) *jsonHandler {
	host, _ := os.Hostname()
	return &jsonHandler{w: w, host: host, min: slog.LevelInfo}
}

// Enabled returns true if the level meets the minimum threshold.
func (h *jsonHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.min
}

// Handle serializes a log record as a JSON line.
//
// Output includes both GELF 1.1 standard fields and human-readable fields:
//
//	{"version":"1.1","host":"goBastion","short_message":"user_login","timestamp":1743200175.123,"level":6,"time":"2026-03-28T00:06:15.123Z","msg":"user_login","_user":"alice"}
func (h *jsonHandler) Handle(_ context.Context, r slog.Record) error {
	m := map[string]any{
		// GELF 1.1 standard fields
		"version":       "1.1",
		"host":          h.host,
		"short_message": r.Message,
		"timestamp":     float64(r.Time.UnixMilli()) / 1000.0,
		"level":         slogLevelToGelf(r.Level),
		// Human-readable fields
		"msg":  r.Message,
		"time": r.Time.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
	}
	// Emit pre-attrs added via log.With(...).
	for _, a := range h.preAttrs {
		m["_"+a.Key] = a.Value.Any()
	}
	// Emit per-record attrs; record attrs win over pre-attrs on key collision.
	r.Attrs(func(a slog.Attr) bool {
		m["_"+a.Key] = a.Value.Any()
		return true
	})

	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	data = bytes.ReplaceAll(data, []byte("\\u003c"), []byte("<"))
	data = bytes.ReplaceAll(data, []byte("\\u003e"), []byte(">"))

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err = h.w.Write(data)
	return err
}

// WithAttrs returns a new handler with the given attributes pre-attached to every record.
func (h *jsonHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, len(h.preAttrs)+len(attrs))
	copy(merged, h.preAttrs)
	copy(merged[len(h.preAttrs):], attrs)
	return &jsonHandler{w: h.w, host: h.host, min: h.min, preAttrs: merged}
}

// WithGroup is a no-op; JSON does not support attribute groups.
func (h *jsonHandler) WithGroup(_ string) slog.Handler { return h }

// multiHandler fans out log records to multiple slog.Handler implementations.
type multiHandler struct {
	handlers []slog.Handler
}

// Enabled returns true if any of the underlying handlers accepts the level.
func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle dispatches the log record to all underlying handlers.
func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			_ = handler.Handle(ctx, r.Clone())
		}
	}
	return nil
}

// WithAttrs propagates the given attributes to all underlying handlers.
func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

// WithGroup propagates the group name to all underlying handlers.
func (h *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}

// syslogHandler routes slog records to the system syslog daemon (best-effort).
type syslogHandler struct {
	writer *syslog.Writer
	level  slog.Level
}

// Enabled always returns true for the syslog handler.
func (h *syslogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle writes the log message to the syslog daemon.
func (h *syslogHandler) Handle(_ context.Context, r slog.Record) error {
	msg := r.Message
	r.Attrs(func(a slog.Attr) bool {
		msg += " " + a.Key + "=" + a.Value.String()
		return true
	})
	switch {
	case r.Level >= slog.LevelError:
		return h.writer.Err(msg)
	case r.Level >= slog.LevelWarn:
		return h.writer.Warning(msg)
	default:
		return h.writer.Info(msg)
	}
}

// WithAttrs is a no-op for the syslog handler.
func (h *syslogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

// WithGroup is a no-op for the syslog handler.
func (h *syslogHandler) WithGroup(_ string) slog.Handler { return h }

// slogWriter bridges the standard log.Logger used by GORM to slog.
type slogWriter struct{ logger *slog.Logger }

// Write forwards log bytes to the underlying syslog writer.
func (w *slogWriter) Write(p []byte) (n int, err error) {
	w.logger.Info(string(p))
	return len(p), nil
}

// plainTextHandler writes human-readable log records to an io.Writer.
type plainTextHandler struct {
	mu       sync.Mutex
	w        io.Writer
	min      slog.Level
	preAttrs []slog.Attr
}

// newPlainTextHandler creates a handler that writes formatted text lines.
func newPlainTextHandler(w io.Writer) *plainTextHandler {
	return &plainTextHandler{w: w, min: slog.LevelInfo}
}

// Enabled returns true if the level meets the minimum threshold.
func (h *plainTextHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.min
}

// Handle writes a human-readable log line:
//
//	2006-01-02 15:04:05.000 LEVEL  message  key1=value1 key2=value2
func (h *plainTextHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Time.Format("2006-01-02 15:04:05.000"))
	b.WriteByte(' ')
	b.WriteString(r.Level.String())
	if len(r.Level.String()) < 5 {
		b.WriteByte(' ')
	}
	b.WriteByte(' ')
	b.WriteString(r.Message)

	emitAttr := func(a slog.Attr) bool {
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		fmt.Fprintf(&b, "%v", a.Value.Any())
		return true
	}
	for _, a := range h.preAttrs {
		emitAttr(a)
	}
	r.Attrs(emitAttr)
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write([]byte(b.String()))
	return err
}

// WithAttrs returns a new handler with pre-attached attributes.
func (h *plainTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, len(h.preAttrs)+len(attrs))
	copy(merged, h.preAttrs)
	copy(merged[len(h.preAttrs):], attrs)
	return &plainTextHandler{w: h.w, min: h.min, preAttrs: merged}
}

// WithGroup is a no-op.
func (h *plainTextHandler) WithGroup(_ string) slog.Handler { return h }

// NewLogger returns a logger writing to /goBastion.log (always)
// and to syslog (best-effort).
//
// Log format is controlled by the LOG_FORMAT environment variable:
//   - "json"  (default): structured JSON lines — compatible with log aggregators
//   - "plain": human-readable timestamped text — useful for local debugging
func NewLogger() *slog.Logger {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		f = os.Stderr
	}

	format := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_FORMAT")))
	var fileHandler slog.Handler
	if format == "plain" {
		fileHandler = newPlainTextHandler(f)
	} else {
		fileHandler = newJSONHandler(f)
	}

	handlers := []slog.Handler{fileHandler}

	if sysWriter, sysErr := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "goBastion"); sysErr == nil {
		handlers = append(handlers, &syslogHandler{writer: sysWriter, level: slog.LevelInfo})
	}

	return slog.New(&multiHandler{handlers: handlers})
}

// NewGormLogger wraps a slog.Logger as a standard log.Logger for use with GORM.
func NewGormLogger(logger *slog.Logger) *log.Logger {
	return log.New(&slogWriter{logger: logger}, "\r\n", 0)
}
