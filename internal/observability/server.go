package observability

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

type Server struct {
	cfg           Config
	database      *sql.DB
	store         *Store
	digest        [32]byte
	started       atomic.Bool
	draining      atomic.Bool
	localDBErrors atomic.Int64
	handler       http.Handler
}

func NewServer(cfg Config, database *gorm.DB, store *Store) (*Server, error) {
	if !cfg.Enabled || !validToken(cfg.Token) || cfg.DBTimeout <= 0 || cfg.DBTimeout > 10*time.Second || cfg.ShutdownTimeout <= 0 || cfg.ShutdownTimeout > 60*time.Second || database == nil || store == nil {
		return nil, errors.New("invalid observation server configuration")
	}
	if err := validateListenAddress(cfg.ListenAddress); err != nil {
		return nil, err
	}
	connection, err := database.DB()
	if err != nil {
		return nil, errors.New("observation database unavailable")
	}
	s := &Server{cfg: cfg, database: connection, store: store, digest: tokenDigest(cfg.Token)}
	// Retain only the fixed-size digest after constructing the authorization gate.
	s.cfg.Token = ""
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", s.live)
	mux.Handle("/readyz", s.authorize(http.HandlerFunc(s.ready)))
	mux.Handle("/startupz", s.authorize(http.HandlerFunc(s.startup)))
	mux.Handle("/metrics", s.authorize(http.HandlerFunc(s.metrics)))
	mux.Handle("/admin/drain", s.authorize(http.HandlerFunc(s.drain)))
	mux.Handle("/admin/", s.authorize(http.NotFoundHandler()))
	s.handler = mux
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.handler }

// SetDraining changes exporter readiness only. Coordinating SSH admission is a
// separate runtime/DB responsibility; this flag does not stop other processes.
func (s *Server) SetDraining(draining bool) { s.draining.Store(draining) }

func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		values := r.Header.Values("Authorization")
		candidate := ""
		validHeader := len(values) == 1
		if validHeader {
			scheme, value, ok := strings.Cut(values[0], " ")
			validHeader = ok && strings.EqualFold(scheme, "Bearer") && len(value) <= 512
			if validHeader {
				candidate = value
			}
		}
		digest := tokenDigest(candidate)
		matches := subtle.ConstantTimeCompare(digest[:], s.digest[:])
		if !validHeader || matches != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="observability"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method && (method != http.MethodGet || r.Method != http.MethodHead) {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		http.NotFound(w, r)
		return
	}
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintln(w, "ok")
}

func (s *Server) collect(ctx context.Context) (Snapshot, error) {
	if err := s.database.PingContext(ctx); err != nil {
		s.recordDBFailure()
		return Snapshot{}, errors.New("observation database unavailable")
	}
	snapshot, err := s.store.Snapshot(ctx)
	if err == nil {
		s.started.Store(true)
		local := s.localDBErrors.Load()
		persisted := snapshot.Counters[DBConnectionErrorsTotal]
		if local > math.MaxInt64-persisted {
			snapshot.Counters[DBConnectionErrorsTotal] = math.MaxInt64
		} else {
			snapshot.Counters[DBConnectionErrorsTotal] = persisted + local
		}
	} else {
		s.recordDBFailure()
	}
	return snapshot, err
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if s.draining.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.DBTimeout)
	defer cancel()
	if _, err := s.collect(ctx); err != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	_, _ = fmt.Fprintln(w, "ready")
}

func (s *Server) startup(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if !s.started.Load() {
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.DBTimeout)
		defer cancel()
		if _, err := s.collect(ctx); err != nil {
			http.Error(w, "not started", http.StatusServiceUnavailable)
			return
		}
	}
	_, _ = fmt.Fprintln(w, "started")
}

func (s *Server) drain(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	s.SetDraining(true)
	_, _ = fmt.Fprintln(w, "exporter readiness draining")
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.DBTimeout)
	defer cancel()
	snapshot, err := s.collect(ctx)
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	var pending *PendingStats
	var stats PendingStats
	if s.cfg.PendingCollector != nil {
		stats, err = s.cfg.PendingCollector(ctx)
	} else {
		stats, err = ScanPending(ctx, s.cfg.RecordingSpool)
	}
	if err == nil {
		pending = &stats
	}
	var output bytes.Buffer
	writeMetrics(&output, snapshot, pending, time.Now())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(output.Bytes())
}

func metric(w *bytes.Buffer, name, kind, help string, value any) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, kind, name, value)
}

// Prometheus text 0.0.4: https://prometheus.io/docs/instrumenting/exposition_formats/
func writeMetrics(w *bytes.Buffer, snapshot Snapshot, pending *PendingStats, now time.Time) {
	metric(w, "gobastion_sessions_active", "gauge", "Registered sessions for this instance; stale registry rows can remain until cleanup.", snapshot.ActiveSessions)
	descriptions := []string{
		"Sessions started by this instance.", "Access decisions denied by this instance.", "Authentication failures observed by this instance.", "MFA failures observed by this instance.", "Synchronization failures observed by this instance.", "Database connection errors observed by this instance.", "Recording archival failures observed by this instance.", "Realm authentication failures observed by this instance.",
	}
	for index, name := range counterNames {
		metric(w, name, "counter", descriptions[index], snapshot.Counters[name])
	}
	fmt.Fprintln(w, "# HELP gobastion_sync_duration_seconds Recorded synchronization durations in seconds.")
	fmt.Fprintln(w, "# TYPE gobastion_sync_duration_seconds summary")
	fmt.Fprintf(w, "gobastion_sync_duration_seconds_count %d\ngobastion_sync_duration_seconds_sum %.9f\n", snapshot.SyncCount, float64(snapshot.SyncNanoseconds)/float64(time.Second))
	if pending != nil {
		age := 0.0
		if !pending.OldestModified.IsZero() {
			age = max(0, now.Sub(pending.OldestModified).Seconds())
		}
		metric(w, "gobastion_recording_pending_bytes", "gauge", "Raw and compressed recording bytes in recognized pending directories of the configured archive tree.", pending.Bytes)
		metric(w, "gobastion_recording_oldest_pending_age_seconds", "gauge", "Seconds since last modification of the oldest measured pending recording file.", age)
	}
}

// Run serves only the configured loopback listener, with bounded HTTP and DB
// operations. Cancellation marks readiness draining before graceful shutdown.
func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return errors.New("observation listener could not start")
	}
	server := &http.Server{Handler: s.handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: s.cfg.DBTimeout + 2*time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	select {
	case err := <-finished:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("observation HTTP server failed")
		}
		return nil
	case <-ctx.Done():
		s.SetDraining(true)
		shutdown, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return errors.New("observation HTTP shutdown failed")
		}
		if err := <-finished; !errors.Is(err, http.ErrServerClosed) {
			return errors.New("observation HTTP server failed during shutdown")
		}
		return nil
	}
}

// Dependency outages cannot be written back to the unavailable dependency.
// Count actual exporter DB failures locally and expose them after recovery.
// This component resets on exporter restart; cross-process event counters stay
// durable in ObservationCounter whenever the shared database is available.
func (s *Server) recordDBFailure() {
	for {
		previous := s.localDBErrors.Load()
		if previous == math.MaxInt64 || s.localDBErrors.CompareAndSwap(previous, previous+1) {
			return
		}
	}
}
