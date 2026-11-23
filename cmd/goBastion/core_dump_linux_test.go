package main

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDisableCoreDumpsInSubprocess(t *testing.T) {
	switch os.Getenv("GOB_TEST_CORE_LIMIT") {
	case "apply":
		if err := disableCoreDumps(); err != nil {
			t.Fatal(err)
		}
		if err := disableCoreDumps(); err != nil {
			t.Fatalf("core limit was not idempotent: %v", err)
		}
		assertCoreLimitZero(t)
		child := exec.Command(os.Args[0], "-test.run=^TestDisableCoreDumpsInSubprocess$")
		child.Env = append(os.Environ(), "GOB_TEST_CORE_LIMIT=check")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("child did not inherit disabled core limit: %v: %s", err, output)
		}
		return
	case "check":
		assertCoreLimitZero(t)
		return
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDisableCoreDumpsInSubprocess$")
	child.Env = append(os.Environ(), "GOB_TEST_CORE_LIMIT=apply")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("core limit subprocess failed: %v: %s", err, output)
	}
}

func assertCoreLimitZero(t *testing.T) {
	t.Helper()
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur != 0 || limit.Max != 0 {
		t.Fatalf("core limit soft=%d hard=%d, want zero", limit.Cur, limit.Max)
	}
}

func TestRunMainRefusesCoreLimitFailure(t *testing.T) {
	previous := setCoreDumpLimit
	setCoreDumpLimit = func(int, *unix.Rlimit) error { return errors.New("fixture limit failure") }
	t.Cleanup(func() { setCoreDumpLimit = previous })
	if got := runMain(); got != 1 {
		t.Fatalf("startup exit status = %d, want failure", got)
	}
}
