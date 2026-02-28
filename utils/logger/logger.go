package logger

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"log/syslog"
	"os"
	"sync"
)

const logFile = "/goBastion.log"

// syslog numeric levels (RFC 5424).
const (
	gelfLevelEmergency = 0
	gelfLevelAlert     = 1
	gelfLevelCritical  = 2
	gelfLevelError     = 3
	gelfLevelWarning   = 4
	gelfLevelNotice    = 5
	gelfLevelInfo      = 6
	gelfLevelDebug     = 7
)

// slogLevelToGelf maps a slog level to a GELF syslog severity number.
func slogLevelToGelf(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return gelfLevelError
	case l >= slog.LevelWarn:
		return gelfLevelWarning
	case l >= slog.LevelInfo:
		return gelfLevelInfo
	default:
		return gelfLevelDebug
	}
}

// gelfHandler writes GELF 1.1 JSON records to an io.Writer.
// Each record is a single line of JSON — compatible with Graylog GELF HTTP/TCP inputs
// and log shippers such as Filebeat or Fluent Bit.
//
// GELF fields produced:
//
//	version        "1.1"
//	host           container hostname
//	short_message  log message
//	timestamp      Unix float64 (seconds + milliseconds)
//	level          syslog numeric level (0-7)
//	_<key>         all additional slog attributes prefixed with _
type gelfHandler struct {
	mu       sync.Mutex
	w        io.Writer
	host     string
	min      slog.Level
	preAttrs []slog.Attr // stored via WithAttrs (e.g. log.With("user", ...))
}

// newGelfHandler creates a new GELF 1.1 log handler writing to w.
func newGelfHandler(w io.Writer) *gelfHandler {
	host, _ := os.Hostname()
	return &gelfHandler{w: w, host: host, min: slog.LevelInfo}
}

// Enabled always returns true; all levels are forwarded to the GELF writer.
func (h *gelfHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.min
}

// Handle serializes a log record as a GELF 1.1 JSON line.
func (h *gelfHandler) Handle(_ context.Context, r slog.Record) error {
	m := map[string]any{
		"version":       "1.1",
		"host":          h.host,
		"short_message": r.Message,
		"timestamp":     float64(r.Time.UnixMilli()) / 1000.0,
		"level":         slogLevelToGelf(r.Level),
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

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err = h.w.Write(data)
	return err
}

// WithAttrs returns a new handler with the given attributes pre-attached to every record.
func (h *gelfHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, len(h.preAttrs)+len(attrs))
	copy(merged, h.preAttrs)
	copy(merged[len(h.preAttrs):], attrs)
	return &gelfHandler{w: h.w, host: h.host, min: h.min, preAttrs: merged}
}

// WithGroup is a no-op; GELF does not support attribute groups.
func (h *gelfHandler) WithGroup(_ string) slog.Handler { return h }

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

// NewLogger returns a logger writing GELF 1.1 JSON to /goBastion.log (always)
// and to syslog (best-effort). The file writer ensures docker logs captures
// events from SSH subprocess invocations of goBastion.
func NewLogger() *slog.Logger {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		f = os.Stderr
	}

	handlers := []slog.Handler{newGelfHandler(f)}

	if sysWriter, sysErr := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "goBastion"); sysErr == nil {
		handlers = append(handlers, &syslogHandler{writer: sysWriter, level: slog.LevelInfo})
	}

	return slog.New(&multiHandler{handlers: handlers})
}

// NewGormLogger wraps a slog.Logger as a standard log.Logger for use with GORM.
func NewGormLogger(logger *slog.Logger) *log.Logger {
	return log.New(&slogWriter{logger: logger}, "\r\n", 0)
}
