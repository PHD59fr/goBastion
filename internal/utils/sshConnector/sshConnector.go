package sshConnector

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	bastionSync "goBastion/internal/utils/sync"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// isNonInteractiveCmd reports whether cmd is a binary file-transfer protocol
// (sftp, scp, rsync) that must not run through ttyrec — a PTY-based recorder
// that would corrupt binary data.
func isNonInteractiveCmd(cmd string) bool {
	c := strings.ToLower(strings.TrimSpace(cmd))
	return strings.Contains(c, "sftp-server") ||
		strings.HasPrefix(c, "scp ") ||
		strings.HasPrefix(c, "rsync ") ||
		strings.Contains(c, "rsync --server")
}

// SshConnection writes the egress key to a temp file and executes an SSH session via ttyrec.
// For non-interactive binary protocols (sftp, scp, rsync) ttyrec is bypassed to avoid
// PTY corruption of binary data. It performs TOFU host key verification before connecting.
func SshConnection(db *gorm.DB, user models.User, access models.AccessRight) error {
	if err := CheckAndUpdateHostKey(db, user, access.Server, access.Port); err != nil {
		return err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting user home directory: %w", err)
	}
	tmpFilePath := filepath.Join(homeDir, ".tmp", fmt.Sprintf("sshkey-%s.pem", uuid.New().String()))

	if err = os.MkdirAll(filepath.Dir(tmpFilePath), 0700); err != nil {
		return fmt.Errorf("error creating ~/.tmp directory: %w", err)
	}
	privateKey := access.PrivateKey + "\n"
	if err = os.WriteFile(tmpFilePath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("error writing private key: %w", err)
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(tmpFilePath)

	knownHostsFile := filepath.Join(config.Get().Paths.HomeBaseDir, strings.ToLower(user.Username), ".ssh", "known_hosts")
	sshArgs := []string{
		"-i", tmpFilePath,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHostsFile,
	}
	// SSH ProxyJump chain: -J hop1,hop2,... (bastion-to-bastion forwarding)
	if len(access.JumpHosts) > 0 {
		sshArgs = append(sshArgs, "-J", strings.Join(access.JumpHosts, ","))
	}
	sshArgs = append(sshArgs,
		access.Username+"@"+access.Server, "-p", strconv.FormatInt(access.Port, 10),
	)
	if access.RemoteCmd != "" {
		sshArgs = append(sshArgs, "--", access.RemoteCmd)
	}

	// Binary protocols must not go through ttyrec: the PTY would corrupt the data stream.
	if access.RemoteCmd != "" && isNonInteractiveCmd(access.RemoteCmd) {
		sshCmd := exec.Command("ssh", sshArgs...)
		sshCmd.Stdin = os.Stdin
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
		if cmdErr := sshCmd.Run(); cmdErr != nil {
			switch cmdErr.Error() {
			case "exit status 100", "exit status 130", "signal: interrupt":
				return nil
			}
			return fmt.Errorf("ssh execution error: %w", cmdErr)
		}
		return nil
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	sessionID := os.Getenv("GOB_SESSION_ID")
	// Sanitize path components to prevent directory traversal.
	safeUser := strings.ReplaceAll(user.Username, "/", "_")
	safeUser = strings.ReplaceAll(safeUser, "..", "_")
	safeServer := strings.ReplaceAll(access.Server, "/", "_")
	safeServer = strings.ReplaceAll(safeServer, "..", "_")
	safeAccessUser := strings.ReplaceAll(access.Username, "/", "_")
	safeAccessUser = strings.ReplaceAll(safeAccessUser, "..", "_")
	dir := fmt.Sprintf("%s/%s/%s/", config.Get().Paths.TtyrecDir, safeUser, safeServer)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating ttyrec dir: %w", err)
	}

	// Non-interactive sessions (remote command) get a _cmd suffix in the filename
	filenameSuffix := ""
	if access.RemoteCmd != "" {
		filenameSuffix = "_cmd"
	}
	if sessionID != "" {
		filenameSuffix += "_sid-" + sessionID
	}
	ttyrecFile := fmt.Sprintf("%s%s.%s:%d_%s%s.ttyrec", dir, safeAccessUser, access.Server, access.Port, timestamp, filenameSuffix)
	ttyrecGzFile := ttyrecFile + ".gz"

	// Create gzip output via temp file + atomic rename to prevent symlink attacks.
	tmpGz, err := os.CreateTemp(dir, "*.gz.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp gzip file: %w", err)
	}
	tmpGzPath := tmpGz.Name()
	defer func() { _ = os.Remove(tmpGzPath) }() // cleanup on failure
	gzipWriter := gzip.NewWriter(tmpGz)

	// Always remove the intermediate .ttyrec file on exit
	defer func() { _ = os.Remove(ttyrecFile) }()

	// cmdDone is signaled when ttyrec exits, so the gzip goroutine knows
	// no more data will be written and can drain to EOF.
	cmdDone := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		var f *os.File
		// Wait for ttyrec to create the file.
		for {
			f, err = os.Open(ttyrecFile)
			if err == nil {
				break
			}
			select {
			case <-cmdDone:
				// ttyrec exited before creating the file — nothing to compress.
				done <- nil
				return
			default:
				time.Sleep(100 * time.Millisecond)
			}
		}
		defer func() { _ = f.Close() }()

		buf := make([]byte, 4096)
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if _, werr := gzipWriter.Write(buf[:n]); werr != nil {
					done <- fmt.Errorf("gzip write error: %w", werr)
					return
				}
			}
			if readErr == io.EOF {
				select {
				case <-cmdDone:
					// ttyrec finished, no more writes expected. Drain once more
					// then exit.
					for {
						n, drainErr := f.Read(buf)
						if n > 0 {
							if _, werr := gzipWriter.Write(buf[:n]); werr != nil {
								done <- fmt.Errorf("gzip write error: %w", werr)
								return
							}
						}
				if drainErr != nil {
						if drainErr == io.EOF {
							done <- nil
						} else {
							done <- fmt.Errorf("file drain error: %w", drainErr)
						}
						return
						}
					}
				default:
					// ttyrec still running, wait for more data.
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			if readErr != nil {
				done <- fmt.Errorf("file read error: %w", readErr)
				return
			}
		}
	}()

	cmd := exec.Command("ttyrec", append([]string{"-f", ttyrecFile, "--", "ssh"}, sshArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Connecting ...")

	cmdErr := cmd.Run()

	// Signal the goroutine that ttyrec has exited, then wait for it to finish draining.
	close(cmdDone)
	gzipErr := <-done

	if cerr := gzipWriter.Close(); cerr != nil {
		return fmt.Errorf("gzip close error: %w", cerr)
	}
	if err := tmpGz.Close(); err != nil {
		return fmt.Errorf("temp file close error: %w", err)
	}

	if gzipErr != nil {
		return fmt.Errorf("gzip compression error: %w", gzipErr)
	}

	// Atomic rename from temp to final path
	if err := os.Rename(tmpGzPath, ttyrecGzFile); err != nil {
		return fmt.Errorf("error renaming gzip file: %w", err)
	}
	// Prevent defer cleanup of successfully renamed temp file
	tmpGzPath = ""

	if cmdErr != nil {
		switch cmdErr.Error() {
		case "exit status 100", "exit status 130", "signal: interrupt":
			return nil
		}
		return fmt.Errorf("ttyrec execution error: %v", cmdErr)
	}

	return nil
}

// hostKeyTTL is how long a stored host key is considered fresh before re-scanning.
// Value is read from configuration.

// CheckAndUpdateHostKey implements TOFU (Trust On First Use) for the target server.
//   - First connection: the scanned key is stored in DB and trusted.
//   - Key unchanged and fresh (< hostKeyTTL): skips the keyscan entirely.
//   - Key changed: returns an error telling the user to run selfReplaceKnownHost.
//
// ssh-keyscan is only invoked when the host is unknown OR the stored entries are stale.
func CheckAndUpdateHostKey(db *gorm.DB, user models.User, server string, port int64) error {
	portStr := strconv.FormatInt(port, 10)

	// Determine host token as stored in known_hosts.
	var hostToken string
	if port == 22 {
		hostToken = server
	} else {
		hostToken = fmt.Sprintf("[%s]:%d", server, port)
	}

	// Fetch existing DB entries for this user.
	var dbEntries []models.KnownHostsEntry
	if err := db.Where("user_id = ?", user.ID).Find(&dbEntries).Error; err != nil {
		return fmt.Errorf("error retrieving known hosts: %w", err)
	}

	// Build map keyType → stored entry for this specific host,
	// and find the most recent update time.
	existing := make(map[string]string)
	var mostRecentUpdate time.Time
	for _, e := range dbEntries {
		parts := strings.Fields(e.Entry)
		if len(parts) >= 3 && parts[0] == hostToken {
			existing[parts[1]] = e.Entry
			if e.UpdatedAt.After(mostRecentUpdate) {
				mostRecentUpdate = e.UpdatedAt
			}
		}
	}

	// If the host is known and entries are still fresh, skip the network scan.
	if len(existing) > 0 && time.Since(mostRecentUpdate) < config.Get().SSH.HostKeyTTL {
		return nil
	}

	// Run ssh-keyscan only when host is unknown or entries are stale.
	out, err := exec.Command("ssh-keyscan", "-p", portStr, "-T", fmt.Sprintf("%d", int(config.Get().SSH.KeyscanTimeout.Seconds())), server).Output()
	if err != nil || len(out) == 0 {
		// Can't scan (unreachable, firewall…) - let SSH fail naturally.
		return nil
	}

	// Parse scanned keys: keyType → full line.
	type scannedKey struct {
		keyType string
		line    string
	}
	var scanned []scannedKey
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		scanned = append(scanned, scannedKey{keyType: parts[1], line: line})
	}
	if len(scanned) == 0 {
		return nil
	}

	// TOFU: nothing known for this host yet — store and trust.
	if len(existing) == 0 {
		for _, sk := range scanned {
			if dbErr := db.Create(&models.KnownHostsEntry{UserID: user.ID, Entry: sk.line}).Error; dbErr != nil {
				slog.Warn("known_hosts_store_failed", slog.String("event", "known_hosts"), slog.String("error", dbErr.Error()))
			}
		}
		return bastionSync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).KnownHostsFromDB(&user)
	}

	// Check each scanned key against stored keys.
	changed := false
	for _, sk := range scanned {
		storedLine, found := existing[sk.keyType]
		if found && storedLine != sk.line {
			changed = true
			break
		}
		if !found {
			// New key type added by the server — store it.
			if dbErr := db.Create(&models.KnownHostsEntry{UserID: user.ID, Entry: sk.line}).Error; dbErr != nil {
				slog.Warn("known_hosts_store_failed", slog.String("event", "known_hosts"), slog.String("error", dbErr.Error()))
			}
		}
	}

	if changed {
		return fmt.Errorf(
			"WARNING: Host key verification failed for %s!\n"+
				"The remote host key has changed since the last connection.\n"+
				"If you trust the new key, run: selfReplaceKnownHost --host %s",
			server, server)
	}

	// Ensure file is up to date (e.g. new key type was added or entries were stale).
	return bastionSync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).KnownHostsFromDB(&user)
}
