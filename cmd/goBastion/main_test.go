package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestShouldBootstrapInstanceConfig(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	os.Args = []string{"goBastion"}
	if !shouldBootstrapInstanceConfig() {
		t.Fatal("expected bootstrap config on normal startup")
	}

	os.Args = []string{"goBastion", "--dbImport"}
	if shouldBootstrapInstanceConfig() {
		t.Fatal("expected bootstrap config to be skipped for --dbImport")
	}
}

func TestReadBootstrapAllowlist(t *testing.T) {
	for _, k := range []string{"DB_DRIVER", "DB_DSN", "EGRESS_ENC_KEY", "EVIL"} {
		t.Setenv(k, "")
	}
	input := "DB_DRIVER=sqlite\nDB_DSN=file:test.db\nEGRESS_ENC_KEY=secret\nEVIL=1\n# comment\nINVALID\n"
	if err := readBootstrap(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DB_DRIVER") != "sqlite" || os.Getenv("DB_DSN") != "file:test.db" || os.Getenv("EGRESS_ENC_KEY") != "secret" {
		t.Fatal("allowed bootstrap vars not set")
	}
	if os.Getenv("EVIL") != "" {
		t.Fatal("non-allowlisted var was set")
	}
}

func TestStripAndParseBootstrapFDArg(t *testing.T) {
	got := stripBootstrapFDArg([]string{"goBastion", "--bootstrap-fd=3", "original-command", "--other"})
	want := []string{"goBastion", "original-command", "--other"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })
	os.Args = []string{"goBastion", "--bootstrap-fd=3"}
	if fd, ok, err := bootstrapFDArg(); !ok || err != nil || fd != 3 {
		t.Fatalf("parse failed: %d %v", fd, ok)
	}
	for _, value := range []string{"99999", "2", "", "invalid"} {
		os.Args = []string{"goBastion", "--bootstrap-fd=" + value}
		if _, ok, err := bootstrapFDArg(); !ok || err == nil {
			t.Fatalf("invalid descriptor %q did not fail closed", value)
		}
	}
	os.Args = []string{"goBastion", "-osh", "--bootstrap-fd=3"}
	if _, ok, err := bootstrapFDArg(); ok || err != nil {
		t.Fatal("command argument interpreted as bootstrap flag")
	}
	got = stripBootstrapFDArg([]string{"goBastion", "--bootstrap-fd=3", "--bootstrap-fd=9"})
	if len(got) != 2 || got[1] != "--bootstrap-fd=9" {
		t.Fatalf("original command was removed: %v", got)
	}
}

func TestReadBootstrapFailureDoesNotApplyPartialEnvironment(t *testing.T) {
	for _, input := range []string{
		"DB_DRIVER=changed\nDB_DSN=invalid\x00value\n",
		"DB_DRIVER=changed\n" + strings.Repeat("x", 1024*1024),
		"DB_DRIVER=changed\n" + strings.Repeat("#ignored\n", 140000),
	} {
		t.Setenv("DB_DRIVER", "original")
		if err := readBootstrap(strings.NewReader(input)); err == nil {
			t.Fatal("invalid or oversized bootstrap accepted")
		}
		if os.Getenv("DB_DRIVER") != "original" {
			t.Fatal("failed bootstrap applied partial configuration")
		}
	}
}

func TestAuthorizedKeysArgIsDedicatedMode(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	for _, tt := range []struct {
		args     []string
		username string
		present  bool
	}{
		{[]string{"goBastion", "--authorizedKeys", "alice"}, "alice", true},
		{[]string{"goBastion", "--authorizedKeys=alice"}, "alice", true},
		{[]string{"goBastion", "--authorizedKeys"}, "", true},
		{[]string{"goBastion", "--authorizedKeys", "alice", "extra"}, "", true},
		{[]string{"goBastion", "--bootstrap-fd=3", "--authorizedKeys=alice"}, "", false},
		{[]string{"goBastion", "-osh", "--authorizedKeys=alice"}, "", false},
	} {
		os.Args = tt.args
		username, present := authorizedKeysArg()
		if username != tt.username || present != tt.present {
			t.Fatalf("args %v: got %q/%v", tt.args, username, present)
		}
	}
}

func TestBoundedIngressLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	blocked := make(chan struct{})
	started := make(chan struct{})
	finished := make(chan struct{})
	defer close(blocked)
	defer cancel()
	go func() {
		<-started
		cancel()
	}()
	lines, err := boundedIngressLookup(ctx, func(context.Context) ([]string, error) {
		close(started)
		<-blocked // Model a driver that does not honor context cancellation.
		close(finished)
		return []string{"late-key"}, nil
	})
	if !errors.Is(err, context.Canceled) || len(lines) != 0 {
		t.Fatalf("canceled lookup published keys: %v, %v", lines, err)
	}
	// The worker can complete after cancellation without blocking on delivery.
	t.Cleanup(func() {
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("lookup worker did not finish")
		}
	})
	lines, err = boundedIngressLookup(context.Background(), func(context.Context) ([]string, error) {
		return []string{"valid-key"}, nil
	})
	if err != nil || len(lines) != 1 || lines[0] != "valid-key" {
		t.Fatalf("successful lookup failed: %v, %v", lines, err)
	}
}
