package transfer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTransferCommandsRejectShellAndClientModes(t *testing.T) {
	for _, raw := range []string{
		"id; # sftp-server", "echo rsync --server", "sh -c 'id' sftp-server",
		"scp -t /tmp; id", "scp -f $(id)", "scp -t /tmp\nid", "scp -S sh -t /tmp",
		"rsync --server . /tmp; id", "rsync --server --daemon . /tmp",
		"rsync --server --rsh=sh . /tmp", "rsync --server -e sh . /tmp",
		"rsync --server -M --rsync-path=sh . /tmp", "rsync --server -esh . /tmp",
		"rsync --server -s . /tmp",
		"rsync --server . /tmp --rsh=sh", "scp -f /tmp -S sh",
		"sftp-server $(id)", "sftp-server | sh", "scp -tf /tmp",
	} {
		t.Run(raw, func(t *testing.T) {
			protocol, _, err := Prepare(raw)
			if err == nil && protocol != "ssh" {
				t.Fatalf("unsafe command accepted as %s", protocol)
			}
		})
	}
}

func TestTransferCommandsKeepLiteralArguments(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	t.Setenv("TRANSFER_ARGS", argsFile)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, bin := range []string{"scp", "rsync", "sftp-server"} {
		if err := os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\nprintf '%s\\000' \"$@\" > \"$TRANSFER_ARGS\"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ raw, protocol, want string }{
		{`scp -t 'two  spaces/file'`, "scpupload", "-t\x00two  spaces/file\x00"},
		{`scp -f 'a;$(id)'`, "scpdownload", "-f\x00a;$(id)\x00"},
		{`scp -t "owner's file"`, "scpupload", "-t\x00owner's file\x00"},
		{`rsync --server -vlogDtpre.iLsfxCIvu . '/tmp/two  spaces'`, "rsync", "--server\x00-vlogDtpre.iLsfxCIvu\x00.\x00/tmp/two  spaces\x00"},
		{`rsync --server --sender -logDtpre.iLsfxCIvu --numeric-ids . /tmp`, "rsync", "--server\x00--sender\x00-logDtpre.iLsfxCIvu\x00--numeric-ids\x00.\x00/tmp\x00"},
		{`sftp-server -e`, "sftp", "-e\x00"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			protocol, command, err := Prepare(tc.raw)
			if err != nil || protocol != tc.protocol {
				t.Fatalf("Prepare: %s, %v", protocol, err)
			}
			if output, err := exec.Command("sh", "-c", command).CombinedOutput(); err != nil {
				t.Fatalf("execute: %s, %v", output, err)
			}
			args, err := os.ReadFile(argsFile)
			if err != nil || string(args) != tc.want {
				t.Fatalf("argv = %q, %v; want %q", args, err, tc.want)
			}
			_, again, err := Prepare(command)
			if err != nil || again != command {
				t.Fatalf("canonical command not stable: %q, %v", again, err)
			}
		})
	}
}
