package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"goBastion/internal/recording/permissions"
)

func executePermissions(args []string, out, diagnostics io.Writer) int {
	if len(args) < 1 || args[0] != "plan" && args[0] != "apply" && args[0] != "rollback" {
		_, _ = fmt.Fprintln(diagnostics, "usage: recording-admin permissions plan|apply|rollback --archive ABS --user NAME --backup ABS [--offline]")
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet("recording-admin permissions "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	archive := flags.String("archive", "", "Absolute archive root")
	account := flags.String("user", "", "Canonical local recording account")
	backup := flags.String("backup", "", "Protected root-owned metadata backup path")
	offline := flags.Bool("offline", false, "Assert all recording writers and instances are stopped")
	retired := flags.Bool("retired", false, "Explicitly migrate a deleted local account to root-owned archived history")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *archive == "" || *account == "" || command != "plan" && (*backup == "" || !*offline) {
		_, _ = fmt.Fprintln(diagnostics, "archive, user, backup, and explicit offline assertion are required for mutation")
		return 2
	}
	var err error
	switch command {
	case "plan":
		var plan permissions.PlanData
		plan, err = permissions.Plan(*archive, *account, *retired)
		if err == nil {
			var encoded []byte
			encoded, err = permissions.Encode(plan)
			if err == nil {
				_, err = out.Write(append(encoded, '\n'))
			}
		}
	case "apply":
		err = permissions.Apply(*archive, *account, *backup, *retired)
	case "rollback":
		err = permissions.Rollback(*archive, *account, *backup, *retired)
	}
	if err != nil {
		// Paths and OS errors may contain operator supplied data. Keep console
		// diagnostics generic; no recording payload is ever read by this tool.
		_, _ = fmt.Fprintf(diagnostics, "permissions %s failed; inspect the protected backup and archive metadata\n", command)
		return 1
	}
	if command != "plan" {
		_, _ = fmt.Fprintf(out, "permissions %s complete\n", command)
	}
	return 0
}
