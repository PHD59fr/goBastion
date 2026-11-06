// Package transfer validates the remote server commands used by file transfers.
package transfer

import (
	"fmt"
	"strings"

	"goBastion/internal/utils/commandline"
)

// Prepare distinguishes a transfer server invocation from an arbitrary SSH
// command. Transfers are rebuilt from literal argv, never forwarded as shell
// source. Only the known server executables and server-mode flags are accepted.
func Prepare(raw string) (protocol, command string, err error) {
	tokens, parseErr := commandline.Scan(raw)
	if parseErr != nil {
		return "", "", parseErr
	}
	if len(tokens) == 0 {
		return "ssh", raw, nil
	}
	bin := tokens[0].Value
	switch bin {
	case "scp", "/usr/bin/scp", "rsync", "/usr/bin/rsync", "sftp-server", "/usr/lib/ssh/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/libexec/sftp-server", "/usr/libexec/openssh/sftp-server":
	default:
		return "ssh", raw, nil
	}
	args := make([]string, len(tokens))
	for i, token := range tokens {
		if token.ShellSyntax || strings.ContainsRune(token.Value, 0) {
			return "", "", fmt.Errorf("transfer commands cannot contain shell operators or expansions")
		}
		args[i] = token.Value
	}
	switch bin {
	case "scp", "/usr/bin/scp":
		protocol, err = scpProtocol(args[1:])
	case "rsync", "/usr/bin/rsync":
		protocol, err = rsyncProtocol(args[1:])
	default:
		protocol = "sftp"
	}
	if err != nil {
		return "", "", err
	}
	for i := range args {
		args[i] = commandline.Quote(args[i])
	}
	return protocol, strings.Join(args, " "), nil
}

func scpProtocol(args []string) (string, error) {
	source, sink := false, false
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		arg := args[i]
		i++
		if arg == "--" {
			break
		}
		if len(arg) < 2 {
			return "", fmt.Errorf("invalid SCP server option")
		}
		for _, flag := range arg[1:] {
			if !strings.ContainsRune("tfrpdvqT", flag) {
				return "", fmt.Errorf("unsupported SCP server option: %s", arg)
			}
			source = source || flag == 'f'
			sink = sink || flag == 't'
		}
	}
	if source == sink || i == len(args) {
		return "", fmt.Errorf("SCP requires one server direction (-t or -f) and a path")
	}
	if sink && len(args[i:]) != 1 {
		return "", fmt.Errorf("SCP upload requires exactly one destination path")
	}
	for _, path := range args[i:] {
		if path == "" || strings.HasPrefix(path, "-") {
			return "", fmt.Errorf("SCP paths must be non-empty and cannot start with '-' (use ./ for relative paths)")
		}
	}
	if sink {
		return "scpupload", nil
	}
	return "scpdownload", nil
}

// rsync's remote server uses compact flag bundles, including the e.PROTOCOL
// compatibility suffix. Client-side command execution/daemon flags are absent
// from this allowlist. Options after the dot are literal file operands.
func rsyncProtocol(args []string) (string, error) {
	if len(args) == 0 || args[0] != "--server" {
		return "", fmt.Errorf("rsync requires --server mode")
	}
	boolOptions := map[string]bool{
		"--sender": true, "--numeric-ids": true, "--delete": true,
		"--delete-before": true, "--delete-during": true, "--delete-delay": true,
		"--delete-after": true, "--delete-excluded": true, "--ignore-existing": true,
		"--existing": true, "--ignore-errors": true, "--force": true,
		"--partial": true, "--append": true, "--append-verify": true,
		"--inplace": true, "--size-only": true, "--checksum": true,
		"--compress": true, "--whole-file": true, "--relative": true,
		"--no-implied-dirs": true, "--omit-dir-times": true,
		"--super": true, "--fake-super": true, "--safe-links": true,
		"--copy-unsafe-links": true, "--munge-links": true, "--remove-source-files": true,
	}
	valueOptions := map[string]bool{
		"--timeout": true, "--bwlimit": true, "--block-size": true,
		"--compress-level": true, "--compress-choice": true, "--checksum-choice": true,
		"--checksum-seed": true, "--max-delete": true, "--min-size": true, "--max-size": true,
		"--modify-window": true, "--partial-dir": true, "--backup-dir": true,
		"--suffix": true, "--chmod": true, "--usermap": true, "--groupmap": true,
		"--chown": true, "--out-format": true, "--log-format": true,
		"--info": true, "--debug": true, "--skip-compress": true,
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "." && i+1 < len(args) {
			for _, path := range args[i+1:] {
				if path == "" || strings.HasPrefix(path, "-") {
					return "", fmt.Errorf("rsync paths must be non-empty and cannot start with '-' (use ./ for relative paths)")
				}
			}
			return "rsync", nil
		}
		if boolOptions[arg] {
			continue
		}
		name, _, hasValue := strings.Cut(arg, "=")
		if valueOptions[name] {
			if !hasValue {
				i++
				if i >= len(args) {
					return "", fmt.Errorf("missing rsync option value")
				}
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 1 {
			flags := arg[1:]
			if before, compat, hasCompat := strings.Cut(flags, "e."); hasCompat {
				flags = before
				for _, flag := range compat {
					if !strings.ContainsRune("iLsfxCIvu", flag) {
						return "", fmt.Errorf("unsupported rsync compatibility option: %s", arg)
					}
				}
			}
			for _, flag := range flags {
				if !strings.ContainsRune("vlogDtprlHAXzcnWqRPEbkKOSUyxFh", flag) {
					return "", fmt.Errorf("unsupported rsync server option: %s", arg)
				}
			}
			continue
		}
		return "", fmt.Errorf("unsupported rsync server option: %s", arg)
	}
	return "", fmt.Errorf("rsync server requires a dot separator and a path")
}
