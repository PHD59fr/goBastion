package sshConnector

import (
	"os/exec"
	"testing"
)

func commandExitError(t *testing.T, code string) error {
	t.Helper()
	return exec.Command("sh", "-c", "exit "+code).Run()
}

func TestCleanInteractiveSessionExit(t *testing.T) {
	if err := commandExitError(t, "1"); !isCleanInteractiveSessionExit(err) {
		t.Fatal("exit status 1 after an interactive shell logout should be accepted")
	}
	if err := commandExitError(t, "254"); !isCleanInteractiveSessionExit(err) {
		t.Fatal("a remote interactive shell exit status should be accepted")
	}
	if err := commandExitError(t, "255"); isCleanInteractiveSessionExit(err) {
		t.Fatal("SSH transport/setup exit status 255 must be reported")
	}
}

func TestExpectedSessionStop(t *testing.T) {
	if err := commandExitError(t, "130"); !isExpectedSessionStop(err) {
		t.Fatal("exit status 130 should be accepted")
	}
	if err := commandExitError(t, "1"); isExpectedSessionStop(err) {
		t.Fatal("exit status 1 is not a generic expected stop")
	}
}
