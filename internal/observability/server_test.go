package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"goBastion/internal/models"
)

const testAuthToken = "observability-test-only-token-0123456789"

func testServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	database := testDatabase(t, "")
	store := testStore(t, database, "sensitive-instance")
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Token = testAuthToken
	cfg.PendingCollector = func(context.Context) (PendingStats, error) { return PendingStats{}, nil }
	service, err := NewServer(cfg, database, store)
	if err != nil {
		t.Fatal(err)
	}
	return service, store
}

func request(service *Server, method, path, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	result := httptest.NewRecorder()
	service.Handler().ServeHTTP(result, req)
	return result
}

func TestProtectedEndpointsRequireBearerAuthentication(t *testing.T) {
	service, _ := testServer(t)
	for _, path := range []string{"/metrics", "/readyz", "/startupz", "/admin/drain", "/admin/future"} {
		for _, authorization := range []string{"", "Bearer incorrect", "Basic " + testAuthToken, "Bearer " + testAuthToken + " extra"} {
			result := request(service, http.MethodGet, path, authorization)
			if result.Code != http.StatusUnauthorized || strings.Contains(result.Body.String(), testAuthToken) {
				t.Fatalf("unprotected endpoint %s: %d", path, result.Code)
			}
		}
	}
	for _, path := range []string{"/metrics", "/readyz", "/startupz"} {
		if result := request(service, http.MethodGet, path, "Bearer "+testAuthToken); result.Code != http.StatusOK {
			t.Fatalf("valid authorization rejected for %s: %d", path, result.Code)
		}
	}
	duplicate := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	duplicate.Header.Add("Authorization", "Bearer "+testAuthToken)
	duplicate.Header.Add("Authorization", "Bearer "+testAuthToken)
	result := httptest.NewRecorder()
	service.Handler().ServeHTTP(result, duplicate)
	if result.Code != http.StatusUnauthorized {
		t.Fatal("ambiguous duplicate authorization accepted")
	}
	if result := request(service, http.MethodPost, "/metrics", "Bearer "+testAuthToken); result.Code != http.StatusMethodNotAllowed {
		t.Fatal("unexpected metrics method accepted")
	}
}

func TestMinimalLivenessIsLocalAndReadinessTracksDrainAndDBFailure(t *testing.T) {
	service, _ := testServer(t)
	if result := request(service, http.MethodGet, "/livez", ""); result.Code != 200 || result.Body.String() != "ok\n" {
		t.Fatal("local liveness failed")
	}
	remote := httptest.NewRequest(http.MethodGet, "/livez", nil)
	remote.RemoteAddr = "192.0.2.1:1234"
	remote.Header.Set("X-Forwarded-For", "127.0.0.1")
	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, remote)
	if response.Code != http.StatusNotFound {
		t.Fatal("remote liveness trusted forwarded headers")
	}
	if result := request(service, http.MethodGet, "/readyz", "Bearer "+testAuthToken); result.Code != 200 {
		t.Fatal("healthy database was not ready")
	}
	if result := request(service, http.MethodPost, "/admin/drain", "Bearer "+testAuthToken); result.Code != 200 {
		t.Fatal("authorized readiness drain failed")
	}
	if result := request(service, http.MethodGet, "/readyz", "Bearer "+testAuthToken); result.Code != 503 {
		t.Fatal("draining exporter remained ready")
	}
	service.SetDraining(false)
	if err := service.database.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/readyz", "/metrics"} {
		if result := request(service, http.MethodGet, path, "Bearer "+testAuthToken); result.Code != 503 || strings.Contains(result.Body.String(), "sql:") {
			t.Fatalf("database failure was hidden/leaked at %s", path)
		}
	}
	if result := request(service, http.MethodGet, "/startupz", "Bearer "+testAuthToken); result.Code != 200 {
		t.Fatal("successful startup state should survive a later dependency outage")
	}
	if result := request(service, http.MethodGet, "/livez", ""); result.Code != 200 {
		t.Fatal("DB outage killed process liveness")
	}
}

func TestReadinessQueriesHaveBoundedDeadlines(t *testing.T) {
	service, _ := testServer(t)
	service.cfg.DBTimeout = 25 * time.Millisecond
	transaction, err := service.database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback() }()
	started := time.Now()
	result := request(service, http.MethodGet, "/readyz", "Bearer "+testAuthToken)
	if result.Code != 503 || time.Since(started) > 500*time.Millisecond {
		t.Fatal("DB readiness blocked without its configured deadline")
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	recovered := request(service, http.MethodGet, "/metrics", "Bearer "+testAuthToken)
	if recovered.Code != 200 || !strings.Contains(recovered.Body.String(), "gobastion_db_connection_errors_total 1\n") {
		t.Fatal("actual exporter DB failure was not exposed after recovery")
	}
}

func TestMetricsExposeRealScopedDataAndFixedNames(t *testing.T) {
	service, store := testServer(t)
	if err := store.Record(context.Background(), SessionsTotal, 4); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(context.Background(), MFAFailuresTotal, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveSyncDuration(context.Background(), 125*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	for _, instance := range []string{"sensitive-instance", "different-instance"} {
		if err := store.db.Create(&models.ActiveSession{InstanceID: instance, Username: "private-username", PID: 123, Kind: "ssh"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	service.cfg.PendingCollector = func(context.Context) (PendingStats, error) {
		return PendingStats{Bytes: 42, OldestModified: time.Now().Add(-time.Hour)}, nil
	}
	response := request(service, http.MethodGet, "/metrics", "Bearer "+testAuthToken)
	body := response.Body.String()
	if response.Code != 200 || response.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatal("incorrect Prometheus response")
	}
	for _, sample := range []string{"gobastion_sessions_active 1\n", "gobastion_sessions_total 4\n", "gobastion_mfa_failures_total 2\n", "gobastion_sync_duration_seconds_count 1\n", "gobastion_sync_duration_seconds_sum 0.125000000\n", "gobastion_recording_pending_bytes 42\n"} {
		if !strings.Contains(body, sample) {
			t.Fatalf("missing real sample %q", sample)
		}
	}
	if strings.Count(body, "# TYPE ") != 12 || !strings.HasSuffix(body, "\n") {
		t.Fatal("incorrect fixed metric family inventory")
	}
	for _, private := range []string{testAuthToken, "private-username", "sensitive-instance", "{"} {
		if strings.Contains(body, private) {
			t.Fatal("metrics exposed secret or unbounded labels")
		}
	}
	service.cfg.PendingCollector = func(context.Context) (PendingStats, error) { return PendingStats{}, context.DeadlineExceeded }
	response = request(service, http.MethodGet, "/metrics", "Bearer "+testAuthToken)
	if response.Code != 200 || strings.Contains(response.Body.String(), "# TYPE gobastion_recording_pending_bytes") || strings.Contains(response.Body.String(), "# TYPE gobastion_recording_oldest_pending_age_seconds") {
		t.Fatal("unknown pending scan was replaced with a false zero")
	}
}

func TestStartupAndReadinessRejectMissingMetricsSchema(t *testing.T) {
	service, store := testServer(t)
	if err := store.db.Migrator().DropTable(&models.ObservationCounter{}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/startupz", "/readyz", "/metrics"} {
		if result := request(service, http.MethodGet, path, "Bearer "+testAuthToken); result.Code != 503 {
			t.Fatalf("missing observation schema was reported healthy at %s", path)
		}
	}
	if err := store.db.AutoMigrate(&models.ObservationCounter{}); err != nil {
		t.Fatal(err)
	}
	if result := request(service, http.MethodGet, "/startupz", "Bearer "+testAuthToken); result.Code != 200 {
		t.Fatal("startup could not recover after schema became ready")
	}
}
