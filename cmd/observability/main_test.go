package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"goBastion/internal/config"
	bastiondb "goBastion/internal/db"
	"goBastion/internal/observability"
)

func TestRootDaemonHealthMetricsAndShutdown(t *testing.T) {
	if os.Getenv("GOB_OBSERVABILITY_TEST_HELPER") == "1" {
		os.Exit(run())
	}
	if os.Getuid() != 0 {
		t.Skip("real root daemon test runs in the disposable container")
	}
	config.ResetForTesting()
	t.Cleanup(config.ResetForTesting)
	for _, name := range []string{"SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY", "OBS_AUTH_TOKEN"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DB_DSN", filepath.Join(dir, "observations.db"))
	t.Setenv("INSTANCE_ID", "root-observation-test")
	config.Load()
	database, err := bastiondb.Init(slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pool.Close() }()
	store, err := observability.NewStore(database, "root-observation-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Record(context.Background(), observability.MFAFailuresTotal, 3); err != nil {
		t.Fatal(err)
	}
	var tokenBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(tokenBytes[:])
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	t.Setenv("OBS_ENABLED", "true")
	t.Setenv("OBS_LISTEN_ADDR", address)
	t.Setenv("OBS_AUTH_TOKEN_FILE", tokenFile)
	t.Setenv("OBS_DB_TIMEOUT", "1s")
	child := exec.Command(os.Args[0], "-test.run=^TestRootDaemonHealthMetricsAndShutdown$")
	child.Env = append(os.Environ(), "GOB_OBSERVABILITY_TEST_HELPER=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- child.Wait() }()
	reaped := false
	defer func() {
		if !reaped {
			select {
			case err := <-finished:
				if err != nil {
					t.Log("exporter child had already exited during cleanup")
				}
			default:
				_ = child.Process.Kill()
				if err := <-finished; err != nil {
					t.Log("exporter child terminated during cleanup")
				}
			}
		}
	}()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/readyz", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err == nil {
			status := response.StatusCode
			_ = response.Body.Close()
			if status == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("root daemon did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	unauthorized, err := client.Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatal("metrics accepted missing credentials")
	}
	request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "gobastion_mfa_failures_total 3") || strings.Contains(string(body), token) {
		t.Fatal("root metrics did not reflect durable observations safely")
	}
	if err := child.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		reaped = true
		if err != nil {
			t.Fatalf("daemon shutdown failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon failed to stop gracefully")
	}
}
