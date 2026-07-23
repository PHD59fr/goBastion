package main

import (
	"os"
	"testing"
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
