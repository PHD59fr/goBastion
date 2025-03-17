package logger

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"log/syslog"
)

type syslogHandler struct {
	writer *syslog.Writer
	level  slog.Level
}

func (h *syslogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *syslogHandler) Handle(ctx context.Context, r slog.Record) error {
	msg := r.Message
	r.Attrs(func(a slog.Attr) bool {
		msg += fmt.Sprintf(" %s=%v", a.Key, a.Value)
		return true
	})
	return h.writer.Info(msg)
}

func (h *syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	return h
}

type slogWriter struct {
	logger *slog.Logger
}

func (w *slogWriter) Write(p []byte) (n int, err error) {
	// Redirect the log message to our slog logger.
	w.logger.Info(string(p))
	return len(p), nil
}

func NewLogger() (*slog.Logger, error) {
	sysWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "goBastion")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	logger := slog.New(&syslogHandler{
		writer: sysWriter,
		level:  slog.LevelInfo,
	})
	return logger, nil
}

func NewGormLogger(logger *slog.Logger) *log.Logger {
	return log.New(&slogWriter{logger: logger}, "\r\n", 0)
}
