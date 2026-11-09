package telemetry

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func cleanEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"OTEL_TRACES_EXPORTER", "OTEL_SDK_DISABLED", "OTEL_SERVICE_NAME", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { current.Store(nil) })
}
func sampled() context.Context {
	return trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled}))
}

func TestSessionRuntimeRejectsCollectorCredentials(t *testing.T) {
	for _, key := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS"} {
		t.Run(key, func(t *testing.T) {
			cleanEnv(t)
			t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.example")
			t.Setenv(key, "Authorization=credential-must-stay-root-only")
			if _, err := ConfigureSessionFromEnv(nil); err == nil || strings.Contains(err.Error(), "credential") {
				t.Fatalf("runtime did not reject credentials safely: %v", err)
			}
			if current.Load() != nil {
				t.Fatal("rejected runtime initialized an exporter")
			}
		})
	}
}

func TestSessionRuntimeAllowsPublicCollectorConfiguration(t *testing.T) {
	cleanEnv(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK", "true")
	p, err := ConfigureSessionFromEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestEndpoint(t *testing.T) {
	for _, tt := range []struct {
		url      string
		loop, ok bool
	}{
		{"https://collector.example:4318", false, true}, {"http://collector.example", true, false}, {"http://127.0.0.1:4318", true, true}, {"http://[::1]:4318", true, true}, {"http://127.0.0.1:4318", false, false}, {"http://localhost:4318", true, false}, {"https://user:secret@collector.example", false, false}, {"https://collector.example?token=secret", false, false}, {"https://collector.example#secret", false, false}, {"https://collector.example:99999", false, false}, {"broken%secret", true, false},
	} {
		t.Run(tt.url, func(t *testing.T) {
			_, err := endpoint(tt.url, tt.loop)
			if (err == nil) != tt.ok {
				t.Fatalf("accepted=%v want%v", err == nil, tt.ok)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("credential exposed")
			}
		})
	}
}
func TestDisabledDoesNotContactCollector(t *testing.T) {
	cleanEnv(t)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	p, err := configureFromEnv(nil, sdktrace.AlwaysSample())
	if err != nil {
		t.Fatal(err)
	}
	_, span := Start(sampled(), "session.authorization", Component("session"))
	span.End()
	if err = p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("disabled exporter contacted collector")
	}
}
func TestOTLPExportUsesClosedAttributes(t *testing.T) {
	cleanEnv(t)
	received := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("unexpected OTLP request %s %s", r.URL.Path, r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing configured header")
		}
		data, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		received <- data
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write([]byte{})
	}))
	defer srv.Close()
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer%20secret")
	p, err := configureFromEnv(nil, sdktrace.AlwaysSample())
	if err != nil {
		t.Fatal(err)
	}
	ctx, span := Start(sampled(), "session.authorization", Component("session"), Protocol("postgresql"), Outcome("username-secret"))
	span.Success()
	span.End()
	if id, _ := TraceIDs(ctx); id == "" {
		t.Fatal("missing trace correlation")
	}
	_, invalid := Start(ctx, "password-secret", Component("session"))
	invalid.End()
	if err = p.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-received:
		var request collector.ExportTraceServiceRequest
		if err = proto.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		if len(request.ResourceSpans) != 1 || len(request.ResourceSpans[0].ScopeSpans) != 1 || len(request.ResourceSpans[0].ScopeSpans[0].Spans) != 1 {
			t.Fatalf("unexpected exported spans: %v", &request)
		}
		if bytes.Contains(body, []byte("secret")) {
			t.Fatal("secret appeared in OTLP payload")
		}
	case <-time.After(time.Second):
		t.Fatal("no OTLP export")
	}
}
func TestConfigurationAndExportErrorsRedacted(t *testing.T) {
	cleanEnv(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://user:password-secret@example.test")
	if _, err := configureFromEnv(nil, sdktrace.AlwaysSample()); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe configuration error: %v", err)
	}
	var logs bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "response-secret")
	}))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK", "true")
	p, err := configureFromEnv(slog.New(slog.NewJSONHandler(&logs, nil)), sdktrace.AlwaysSample())
	if err != nil {
		t.Fatal(err)
	}
	_, span := Start(sampled(), "session.authorization")
	span.End()
	err = p.Shutdown(context.Background())
	if err != nil && strings.Contains(err.Error(), "secret") {
		t.Fatal("secret shutdown error")
	}
	if strings.Contains(logs.String(), "secret") {
		t.Fatal("secret log")
	}
}
func TestShutdownCancellationAndBoundedQueue(t *testing.T) {
	cleanEnv(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { releaseOnce.Do(func() { close(release) }); srv.Close() }()
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK", "true")
	p, err := configureFromEnv(nil, sdktrace.AlwaysSample())
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	for range 4096 {
		_, span := Start(sampled(), "dbbroker.connect", Protocol("mysql"))
		span.End()
	}
	if time.Since(begin) > time.Second {
		t.Fatal("queue blocked callers")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	begin = time.Now()
	_ = p.Shutdown(ctx)
	if time.Since(begin) > 500*time.Millisecond {
		t.Fatal("cancelled shutdown blocked")
	}
	releaseOnce.Do(func() { close(release) })
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatal("background cleanup did not finish after collector release")
	}
}

func TestRemoteParentAndTraceStateCannotControlLocalExport(t *testing.T) {
	cleanEnv(t)
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		received <- body
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK", "true")
	provider, err := configureFromEnv(nil, sdktrace.AlwaysSample())
	if err != nil {
		t.Fatal(err)
	}
	state, err := trace.ParseTraceState("untrusted=credential-marker")
	if err != nil {
		t.Fatal(err)
	}
	remote := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{9}, SpanID: trace.SpanID{9}, TraceFlags: trace.FlagsSampled, TraceState: state, Remote: true})
	remoteContext := trace.ContextWithRemoteSpanContext(context.Background(), remote)
	if id, _ := TraceIDs(remoteContext); id != "" {
		t.Fatal("untrusted remote context was accepted for log correlation")
	}
	ctx, span := Start(remoteContext, "session.authorization")
	local := trace.SpanContextFromContext(ctx)
	if local.TraceID() == remote.TraceID() || local.TraceState().Len() != 0 {
		t.Fatal("remote identity or private tracestate reached the local trace")
	}
	childCtx, child := Start(ctx, "dbbroker.connect")
	if trace.SpanContextFromContext(childCtx).TraceID() != local.TraceID() {
		t.Fatal("trusted local parent correlation was lost")
	}
	child.End()
	span.End()
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-received:
		if bytes.Contains(body, []byte("credential-marker")) {
			t.Fatal("remote tracestate leaked into OTLP")
		}
	case <-time.After(time.Second):
		t.Fatal("no local export")
	}
	current.Store(nil)
	if id, _ := TraceIDs(ctx); id != "" {
		t.Fatal("disabled provider retained trace correlation")
	}
}
