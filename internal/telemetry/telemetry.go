// Package telemetry provides optional, bounded tracing without request payloads.
// Only the fixed operation names and enumerated attributes below can be exported.
package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const ShutdownTimeout = 3 * time.Second
const exportTimeout = 2 * time.Second

// Attribute has no exported fields: callers cannot attach arbitrary data.
type Attribute struct{ value attribute.KeyValue }

func enumerated(key, value string, allowed ...string) Attribute {
	for _, candidate := range allowed {
		if value == candidate {
			return Attribute{attribute.String(key, value)}
		}
	}
	return Attribute{}
}
func Component(value string) Attribute {
	return enumerated("gobastion.component", value, "session", "sync", "dbbroker", "recording", "startup")
}
func Protocol(value string) Attribute {
	return enumerated("db.system.name", value, "mysql", "postgresql", "redis")
}
func Outcome(value string) Attribute {
	return enumerated("gobastion.outcome", value, "success", "failure", "denied", "cancelled")
}

// Span deliberately excludes payload, exception, event, and arbitrary attribute APIs.
type Span struct{ span trace.Span }

func (s Span) End() {
	if s.span != nil {
		s.span.End()
	}
}
func (s Span) Success() {
	if s.span != nil {
		s.span.SetAttributes(attribute.String("gobastion.outcome", "success"))
		s.span.SetStatus(codes.Ok, "")
	}
}
func (s Span) Failure() {
	if s.span != nil {
		s.span.SetAttributes(attribute.String("gobastion.outcome", "failure"))
		s.span.SetStatus(codes.Error, "")
	}
}

type Provider struct {
	sdk          *sdktrace.TracerProvider
	tracer       trace.Tracer
	shutdownOnce sync.Once
	shutdownDone chan struct{}
	shutdownErr  error
	transport    *http.Transport
}

var current atomic.Pointer[Provider]
var noTracer = noop.NewTracerProvider().Tracer("goBastion")

type localSpanKey struct{}
type localSpan struct {
	provider *Provider
	context  trace.SpanContext
}

func Start(ctx context.Context, name string, attrs ...Attribute) (context.Context, Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	switch name {
	case "session.authorization", "sync.reconcile", "dbbroker.connect", "recording.archive", "recording.publish", "startup":
	default:
		return ctx, Span{}
	}
	tracer := noTracer
	p := current.Load()
	if p != nil {
		tracer = p.tracer
	}
	values := make([]attribute.KeyValue, 0, 3)
	for _, a := range attrs {
		if a.value.Key != "" {
			values = append(values, a.value)
		}
		if len(values) == 3 {
			break
		}
	}
	options := []trace.SpanStartOption{trace.WithAttributes(values...)}
	parent, ours := ctx.Value(localSpanKey{}).(localSpan)
	// Public contexts may carry remote tracestate, sampling decisions or IDs.
	// Only parents created by this provider are allowed to influence export.
	if !ours || parent.provider != p || !parent.context.Equal(trace.SpanContextFromContext(ctx)) {
		options = append(options, trace.WithNewRoot())
	}
	ctx, span := tracer.Start(ctx, name, options...)
	ctx = context.WithValue(ctx, localSpanKey{}, localSpan{p, span.SpanContext()})
	return ctx, Span{span}
}

// TraceIDs returns correlation identifiers only for locally recorded spans.
func TraceIDs(ctx context.Context) (string, string) {
	if ctx == nil {
		return "", ""
	}
	p := current.Load()
	if p == nil || p.sdk == nil {
		return "", ""
	}
	owner, ours := ctx.Value(localSpanKey{}).(localSpan)
	s := trace.SpanContextFromContext(ctx)
	if !ours || owner.provider != p || !owner.context.Equal(s) || s.IsRemote() || !s.IsValid() || !s.IsSampled() {
		return "", ""
	}
	return s.TraceID().String(), s.SpanID().String()
}

func configurationError() error { return errors.New("invalid tracing configuration") }

// endpoint accepts HTTPS collectors, or explicitly allowed numeric loopback HTTP.
// Userinfo, query parameters and fragments cannot carry credentials in URLs.
func endpoint(raw string, loopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, configurationError()
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !loopback || ip == nil || !ip.IsLoopback() {
			return nil, configurationError()
		}
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, configurationError()
		}
	}
	return u, nil
}

func headers(raw string) (map[string]string, error) {
	result := map[string]string{}
	if len(raw) > 8192 {
		return nil, configurationError()
	}
	if raw == "" {
		return result, nil
	}
	for _, part := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		decoded, err := url.PathUnescape(v)
		if !ok || err != nil || k == "" || strings.ContainsAny(decoded, "\r\n") {
			return nil, configurationError()
		}
		for _, c := range k {
			if !strings.ContainsRune("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", c) {
				return nil, configurationError()
			}
		}
		result[k] = decoded
	}
	return result, nil
}

// ConfigureFromEnv is disabled unless OTEL_TRACES_EXPORTER=otlp is explicit.
// Supported configuration: OTEL_SERVICE_NAME, OTEL_EXPORTER_OTLP[_TRACES]_ENDPOINT,
// OTEL_EXPORTER_OTLP[_TRACES]_HEADERS, and OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK.
// Queue (256), batch (64), export (2s), retries (disabled), and shutdown (3s) are
// fixed bounds; SDK environment defaults cannot override them.
func ConfigureFromEnv(log *slog.Logger) (*Provider, error) {
	return configureFromEnv(log, sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.1)))
}

// ConfigureSessionFromEnv is the multiprocess runtime's configuration boundary.
// Collector credentials must remain in a separate trusted collector: sudo
// wrappers intentionally forward only public tracing settings to SSH sessions.
// Refuse headers at startup rather than silently losing authenticated session
// exports or distributing a root collector credential to unprivileged users.
func ConfigureSessionFromEnv(log *slog.Logger) (*Provider, error) {
	if os.Getenv("OTEL_TRACES_EXPORTER") == "otlp" && os.Getenv("OTEL_SDK_DISABLED") != "true" {
		if os.Getenv("OTEL_EXPORTER_OTLP_HEADERS") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS") != "" {
			return nil, configurationError()
		}
	}
	return ConfigureFromEnv(log)
}

func configureFromEnv(log *slog.Logger, sampler sdktrace.Sampler) (*Provider, error) {
	p := &Provider{tracer: noTracer}
	exporter := os.Getenv("OTEL_TRACES_EXPORTER")
	if exporter == "" || exporter == "none" || os.Getenv("OTEL_SDK_DISABLED") == "true" {
		current.Store(p)
		return p, nil
	}
	if exporter != "otlp" {
		return nil, configurationError()
	}
	loopback := false
	if raw := os.Getenv("OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK"); raw != "" {
		var err error
		loopback, err = strconv.ParseBool(raw)
		if err != nil {
			return nil, configurationError()
		}
	}
	raw := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	tracesEndpoint := raw != ""
	if raw == "" {
		raw = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if raw == "" {
		return nil, configurationError()
	}
	u, err := endpoint(raw, loopback)
	if err != nil {
		return nil, err
	}
	if !tracesEndpoint {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/traces"
		u.RawPath = ""
	}
	rawHeaders, exists := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_HEADERS")
	if !exists {
		rawHeaders = os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")
	}
	h, err := headers(rawHeaders)
	if err != nil {
		return nil, err
	}
	service := os.Getenv("OTEL_SERVICE_NAME")
	if service == "" {
		service = "goBastion"
	}
	if len(service) > 128 {
		return nil, configurationError()
	}
	for _, c := range service {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", c) {
			return nil, configurationError()
		}
	}
	if log == nil {
		log = slog.Default()
	}
	// SDK errors can contain collector response bodies or request URLs. Never log them.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) { log.Warn("trace_export_failed") }))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = exportTimeout
	transport.MaxResponseHeaderBytes = 16 << 10
	transport.MaxIdleConns = 2
	transport.MaxIdleConnsPerHost = 2
	client := &http.Client{Transport: transport, Timeout: exportTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("collector redirect disabled") }}
	exp, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(u.String()), otlptracehttp.WithEncoding(otlptracehttp.EncodingProtobuf), otlptracehttp.WithHeaders(h), otlptracehttp.WithTimeout(exportTimeout), otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}), otlptracehttp.WithHTTPClient(client), otlptracehttp.WithCompression(otlptracehttp.NoCompression))
	if err != nil {
		transport.CloseIdleConnections()
		return nil, configurationError()
	}
	p.sdk = sdktrace.NewTracerProvider(sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", service))), sdktrace.WithSampler(sampler), sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{AttributeCountLimit: 4, AttributeValueLengthLimit: 128, EventCountLimit: 0, LinkCountLimit: 0}), sdktrace.WithBatcher(exp, sdktrace.WithMaxQueueSize(256), sdktrace.WithMaxExportBatchSize(64), sdktrace.WithBatchTimeout(time.Second), sdktrace.WithExportTimeout(exportTimeout)))
	p.tracer = p.sdk.Tracer("goBastion")
	p.transport = transport
	current.Store(p)
	return p, nil
}

// Shutdown flushes pending spans within the smaller of ctx's deadline and 3s.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.sdk == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.shutdownOnce.Do(func() {
		p.shutdownDone = make(chan struct{})
		go func() {
			// The SDK skips processor cleanup when given an already-canceled
			// context. Keep cleanup independent of an impatient caller.
			cleanup, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
			defer cancel()
			defer close(p.shutdownDone)
			p.shutdownErr = p.sdk.Shutdown(cleanup)
			if p.transport != nil {
				p.transport.CloseIdleConnections()
			}
		}()
	})
	bounded, cancel := context.WithTimeout(ctx, ShutdownTimeout)
	defer cancel()
	select {
	case <-p.shutdownDone:
		if p.shutdownErr == nil {
			return nil
		}
	case <-bounded.Done():
	}
	return errors.New("tracing shutdown incomplete")
}
func ShutdownDefault(ctx context.Context) error { return current.Load().Shutdown(ctx) }
