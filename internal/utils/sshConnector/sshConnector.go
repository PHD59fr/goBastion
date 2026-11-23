package sshConnector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"log/slog"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/recording"
	"goBastion/internal/recording/archive"
	bastionSync "goBastion/internal/utils/sync"
	"goBastion/internal/utils/transfer"
	"goBastion/internal/utils/validation"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// isNonInteractiveCmd reports whether cmd is a binary file-transfer protocol
// (sftp, scp, rsync) that must not run through ttyrec — a PTY-based recorder
// that would corrupt binary data.
func isNonInteractiveCmd(cmd string) bool {
	protocol, _, err := transfer.Prepare(cmd)
	return err == nil && protocol != "ssh"
}

// isExpectedSessionStop reports exit statuses used when a user deliberately
// leaves a session (for example Ctrl-C in the prompt).
func isExpectedSessionStop(err error) bool {
	if err == nil {
		return true
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitCode() {
		case 100, 130:
			return true
		}
	}
	return err.Error() == "signal: interrupt"
}

// isCleanInteractiveSessionExit reports an SSH exit caused by the remote
// interactive shell ending. SSH forwards the shell's last exit code; Ctrl-D
// can therefore legitimately result in 1 rather than 0.  OpenSSH reserves
// 255 for its own connection/setup errors, which must still be reported.
func isCleanInteractiveSessionExit(err error) bool {
	if isExpectedSessionStop(err) {
		return true
	}

	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() >= 0 && exitErr.ExitCode() != 255
}

type sshClientErrorCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *sshClientErrorCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const max = 4096
	if c.buf.Len() < max {
		remaining := max - c.buf.Len()
		if len(p) > remaining {
			_, _ = c.buf.Write(p[:remaining])
		} else {
			_, _ = c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *sshClientErrorCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func formatSSHClientFailure(err error, capture *sshClientErrorCapture, target string) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 255 {
		return fmt.Errorf("remote SSH session failed: %w", err)
	}
	msg := ""
	if capture != nil {
		msg = capture.String()
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "operation timed out"), strings.Contains(lower, "connection timed out"), strings.Contains(lower, "timed out"):
		return fmt.Errorf("unable to reach %s: connection timed out", target)
	case strings.Contains(lower, "connection refused"):
		return fmt.Errorf("unable to reach %s: connection refused", target)
	case strings.Contains(lower, "no route to host"):
		return fmt.Errorf("unable to reach %s: no route to host", target)
	case strings.Contains(lower, "network is unreachable"):
		return fmt.Errorf("unable to reach %s: network is unreachable", target)
	case strings.Contains(lower, "could not resolve hostname"), strings.Contains(lower, "name or service not known"), strings.Contains(lower, "nodename nor servname provided"):
		return fmt.Errorf("unable to reach %s: host name could not be resolved", target)
	case strings.Contains(lower, "permission denied"), strings.Contains(lower, "authentication failed"):
		return fmt.Errorf("authentication failed for %s", target)
	case strings.Contains(lower, "host key verification failed"), strings.Contains(lower, "remote host identification has changed"):
		return fmt.Errorf("host key verification failed for %s", target)
	case strings.Contains(lower, "broken pipe"), strings.Contains(lower, "connection reset"):
		return fmt.Errorf("connection to %s was interrupted", target)
	default:
		line := lastSSHDiagnosticLine(msg)
		if line != "" {
			return fmt.Errorf("unable to connect to %s: %s: %w", target, line, err)
		}
		return fmt.Errorf("unable to connect to %s: SSH client exited with status 255: %w", target, err)
	}
}

func lastSSHDiagnosticLine(msg string) string {
	for _, raw := range strings.Split(strings.ReplaceAll(msg, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Warning:") || strings.HasPrefix(line, "Pseudo-terminal will not be allocated") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "ssh: "))
	}
	return ""
}

// SshConnection writes the egress key to a temp file and executes an SSH session via ttyrec.
// For non-interactive binary protocols (sftp, scp, rsync) ttyrec is bypassed to avoid
// PTY corruption of binary data. It performs TOFU host key verification before connecting.
func SshConnection(db *gorm.DB, user models.User, access models.AccessRight) error {
	policy, err := recording.LoadLivePolicy()
	if err != nil {
		return err
	}
	defer policy.Close()
	if policy != nil && (!config.Get().TTYRec.Enabled || isNonInteractiveCmd(access.RemoteCmd)) {
		return errors.New("encrypted recording policy requires a recorded interactive transport")
	}
	access.Server = validation.UnbracketHost(access.Server)
	if err := CheckAndUpdateHostKey(db, user, access.Server, access.Port); err != nil {
		return err
	}

	// Session duration limit (0 = unlimited). Applies to both the direct ssh
	// path and the ttyrec-wrapped path below.
	runCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer stopSignals()
	if d := config.Get().Session.MaxSessionDuration; d > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(runCtx, time.Duration(d))
		defer cancel()
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
	// Close a session channel that carries no traffic for the configured
	// interval. ServerAliveInterval only detects an unresponsive peer and does
	// not implement user inactivity, whereas ChannelTimeout does.
	if idleTimeout := time.Duration(config.Get().Session.IdleTimeout); idleTimeout > 0 {
		seconds := int(idleTimeout.Seconds())
		sshArgs = append(sshArgs,
			"-o", fmt.Sprintf("ChannelTimeout=session=%ds", seconds),
		)
	}
	// Ignore account-controlled ~/.ssh/config, which can execute local commands
	// through Match exec, ProxyCommand or LocalCommand. A generated jump config
	// replaces this fixed file and is inherited by ProxyJump subprocesses.
	sshConfigPath := "/dev/null"
	// SSH ProxyJump chain: -J hop1,hop2,... (bastion-to-bastion forwarding)
	if len(access.JumpHosts) > 0 {
		configuration, aliases, err := jumpConfig(db, user, access.JumpHosts, tmpFilePath, knownHostsFile)
		if err != nil {
			return fmt.Errorf("prepare SSH jumps: %w", err)
		}
		defer func() { _ = os.Remove(configuration) }()
		sshConfigPath = configuration
		sshArgs = append(sshArgs, "-J", strings.Join(aliases, ","))
	}
	sshArgs = append([]string{"-F", sshConfigPath}, sshArgs...)
	sshArgs = append(sshArgs,
		"-p", strconv.FormatInt(access.Port, 10), "-l", access.Username,
		"--", access.Server,
	)
	if access.RemoteCmd != "" {
		sshArgs = append(sshArgs, access.RemoteCmd)
	}

	// Binary protocols must not go through ttyrec: the PTY would corrupt the data stream.
	if access.RemoteCmd != "" && isNonInteractiveCmd(access.RemoteCmd) {
		sshCmd := exec.CommandContext(runCtx, "ssh", sshArgs...)
		// Revocation can exit the session process without running its defers.
		// Ask the kernel to stop SSH as well so it cannot retain the transport.
		sshCmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGHUP}
		sshCmd.Stdin = os.Stdin
		sshCmd.Stdout = os.Stdout
		capture := &sshClientErrorCapture{}
		sshCmd.Stderr = capture
		if cmdErr := sshCmd.Run(); cmdErr != nil {
			if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("⛔ Session ended: maximum session duration reached")
			}
			if isExpectedSessionStop(cmdErr) {
				return nil
			}
			return formatSSHClientFailure(cmdErr, capture, access.Server)
		}
		return nil
	}

	// Recording disabled: run ssh directly (no ttyrec wrapper) but still honour
	// the session duration limit via runCtx.
	if !config.Get().TTYRec.Enabled {
		sshCmd := exec.CommandContext(runCtx, "ssh", sshArgs...)
		sshCmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGHUP}
		sshCmd.Stdin = os.Stdin
		sshCmd.Stdout = os.Stdout
		capture := &sshClientErrorCapture{}
		sshCmd.Stderr = capture
		if cmdErr := sshCmd.Run(); cmdErr != nil {
			if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("⛔ Session ended: maximum session duration reached")
			}
			if access.RemoteCmd == "" && isCleanInteractiveSessionExit(cmdErr) {
				return nil
			}
			if isExpectedSessionStop(cmdErr) {
				return nil
			}
			return formatSSHClientFailure(cmdErr, capture, access.Server)
		}
		return nil
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	sessionID := os.Getenv("GOB_SESSION_ID")
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	// Sanitize path components to prevent directory traversal.
	safeUser := strings.ReplaceAll(user.Username, "/", "_")
	safeUser = strings.ReplaceAll(safeUser, "..", "_")
	safeServer := strings.ReplaceAll(access.Server, "/", "_")
	safeServer = strings.ReplaceAll(safeServer, "..", "_")
	safeAccessUser := strings.ReplaceAll(access.Username, "/", "_")
	safeAccessUser = strings.ReplaceAll(safeAccessUser, "..", "_")
	dir := fmt.Sprintf("%s/%s/%s/", config.Get().Paths.TtyrecDir, safeUser, safeServer)

	// Non-interactive sessions (remote command) get a _cmd suffix in the filename
	filenameSuffix := ""
	if access.RemoteCmd != "" {
		filenameSuffix = "_cmd"
	}
	if sessionID != "" {
		filenameSuffix += "_sid-" + sessionID
	}
	ttyrecFile := fmt.Sprintf("%s%s.%s:%d_%s%s.ttyrec", dir, safeAccessUser, safeServer, access.Port, timestamp, filenameSuffix)
	ttyrecGzFile := ttyrecFile + ".gz"
	if policy != nil {
		ttyrecGzFile = ttyrecFile + ".gobrec"
	}
	spool, err := recording.NewSSHSpool(config.Get().Paths.TtyrecDir, filepath.Join(safeUser, safeServer))
	if err != nil {
		if strings.Contains(err.Error(), "unsafe recording") || strings.Contains(err.Error(), "provision an isolated archive") || strings.Contains(err.Error(), "recording account provisioning requires") {
			slog.Error("recording_integrity_failed",
				slog.String("user", user.Username),
				slog.String("archive", config.Get().Paths.TtyrecDir),
				slog.String("path", filepath.Join(safeUser, safeServer)),
				slog.Any("error", err),
			)
			return fmt.Errorf("creating recording spool: recording storage integrity check failed")
		}
		slog.Error("recording_spool_failed", slog.String("user", user.Username), slog.Any("error", err))
		return fmt.Errorf("creating recording spool: recording storage unavailable")
	}
	ttyrecFile = filepath.Join(spool.WorkPath, filepath.Base(ttyrecFile))
	published := false
	retainSpool := false
	var lock *os.File
	defer func() {
		defer func() {
			if lock != nil {
				_ = lock.Close()
			}
		}()
		if retainSpool {
			slog.Error("ssh_recording_retained", "user", user.Username, "spool", spool.Path, "destination", ttyrecGzFile)
			if err := spool.Close(false); err != nil {
				slog.Warn("ssh_spool_close_failed", "error", err)
			}
			return
		}
		if !published {
			info, statErr := os.Stat(ttyrecFile)
			if (statErr == nil && info.Size() > 0) || (statErr != nil && !os.IsNotExist(statErr)) {
				slog.Error("ssh_recording_retained", "user", user.Username, "spool", spool.Path, "destination", ttyrecGzFile)
				if err := spool.Close(false); err != nil {
					slog.Warn("ssh_spool_close_failed", "error", err)
				}
				return
			}
		}
		if err := spool.Close(true); err != nil {
			slog.Warn("ssh_spool_cleanup_failed", "error", err)
		}
	}()

	lock, err = recording.PrepareCapture(spool.WorkPath, filepath.Join(safeUser, safeServer, filepath.Base(ttyrecGzFile)), ttyrecFile, policy != nil)
	if err != nil {
		return fmt.Errorf("prepare SSH recording: %w", err)
	}

	// Create gzip output via temp file + atomic rename to prevent symlink attacks.
	tmpGz, err := os.CreateTemp(spool.WorkPath, "*.gz.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp gzip file: %w", err)
	}
	defer func() { _ = tmpGz.Close() }()
	if err = tmpGz.Chmod(0640); err != nil {
		_ = tmpGz.Close()
		return fmt.Errorf("setting recording permissions: %w", err)
	}
	tmpGzPath := tmpGz.Name()
	gzipWriter, err := recording.NewCaptureWriter(tmpGz, policy, archive.Provenance{SessionID: sessionID, BastionID: config.InstanceID(), Protocol: "ssh", Account: user.Username, Target: access.Server, StartedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	defer gzipWriter.Abort()

	// cmdDone is signaled when ttyrec exits. A capture failure cancels the
	// command immediately so the SSH client cannot continue unrecorded.
	recordingCtx, stopRecording := context.WithCancel(runCtx)
	defer stopRecording()
	cmdDone := make(chan struct{})
	abortCapture := make(chan struct{})
	done := make(chan error, 1)

	cmd := exec.CommandContext(recordingCtx, "ttyrec", append([]string{"-f", ttyrecFile, "--", "ssh"}, sshArgs...)...)
	completion, err := recording.ConfigureRecorder(cmd, lock)
	if err != nil {
		return fmt.Errorf("configure SSH recorder: %w", err)
	}
	defer completion.Close()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	capture := &sshClientErrorCapture{}
	cmd.Stderr = capture
	go func() {
		done <- recording.StreamRaw(ttyrecFile, gzipWriter, cmdDone, abortCapture, stopRecording)
	}()

	fmt.Println("Connecting ...")

	cmdErr := cmd.Run()
	completionErr := completion.Wait(recording.RecorderExitTimeout)

	// All inherited recorder lock copies must close before the final drain.
	if completionErr != nil {
		retainSpool = true
		close(abortCapture)
	}
	close(cmdDone)
	gzipErr := <-done
	if completionErr != nil {
		return fmt.Errorf("recorder did not finish cleanly: %w", completionErr)
	}

	if gzipErr != nil {
		return fmt.Errorf("recording stream error: %w", gzipErr)
	}
	gzipCloseErr := gzipWriter.CloseAfterRecorder(cmdErr, runCtx.Err())
	syncErr := tmpGz.Sync()
	closeErr := tmpGz.Close()
	if err := errors.Join(gzipCloseErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("finalizing SSH recording: %w", err)
	}

	// Atomic rename from temp to final path
	if err := recording.Publish(config.Get().Paths.TtyrecDir, tmpGzPath, filepath.Join(safeUser, safeServer, filepath.Base(ttyrecGzFile)), os.Geteuid()); err != nil {
		return fmt.Errorf("error publishing gzip file: %w", err)
	}
	published = true

	if cmdErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("⛔ Session ended: maximum session duration reached")
		}
		if access.RemoteCmd == "" && isCleanInteractiveSessionExit(cmdErr) {
			return nil
		}
		if isExpectedSessionStop(cmdErr) {
			return nil
		}
		return formatSSHClientFailure(cmdErr, capture, access.Server)
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
	server = validation.UnbracketHost(server)
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
	matched := make([]models.KnownHostsEntry, 0, len(dbEntries))
	var mostRecentUpdate time.Time
	for _, e := range dbEntries {
		parts := strings.Fields(e.Entry)
		if len(parts) >= 3 && parts[0] == hostToken {
			existing[parts[1]] = e.Entry
			matched = append(matched, e)
			if e.UpdatedAt.After(mostRecentUpdate) {
				mostRecentUpdate = e.UpdatedAt
			}
		}
	}

	// If the host is known and entries are still fresh, skip the network scan.
	// If the file already exists on disk there is nothing to do — it was
	// written by a prior KnownHostsFromDB call and the user can read it.
	if len(existing) > 0 && time.Since(mostRecentUpdate) < time.Duration(config.Get().SSH.HostKeyTTL) {
		khPath := filepath.Join(config.Get().Paths.HomeBaseDir, strings.ToLower(user.Username), ".ssh", "known_hosts")
		if _, err := os.Stat(khPath); err == nil {
			return nil
		}
		return bastionSync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).KnownHostsFromDB(&user)
	}

	// Run ssh-keyscan only when host is unknown or entries are stale.
	out, err := exec.Command("ssh-keyscan", "-p", portStr, "-T", fmt.Sprintf("%d", int(time.Duration(config.Get().SSH.KeyscanTimeout).Seconds())), "--", server).Output()
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
			// A new algorithm is still a host identity change. Do not silently
			// expand trust for a host that was already enrolled.
			changed = true
			break
		}
	}

	if changed {
		return fmt.Errorf(
			"WARNING: Host key verification failed for %s!\n"+
				"The remote host key has changed since the last connection.\n"+
				"If you trust the new key, run: selfReplaceKnownHost --host %s",
			server, server)
	}

	// Record the successful verification so the TTL covers subsequent
	// connections. Only a scan that matched every stored key reaches this
	// point; errors and key or algorithm changes return before the update.
	if len(matched) > 0 {
		ids := make([]uuid.UUID, 0, len(matched))
		for _, entry := range matched {
			ids = append(ids, entry.ID)
		}
		if err := db.Model(&models.KnownHostsEntry{}).Where("id IN ?", ids).Update("updated_at", time.Now()).Error; err != nil {
			slog.Warn("known_hosts_verification_timestamp_failed", slog.String("event", "known_hosts"), slog.String("error", err.Error()))
		}
	}

	// Ensure file is up to date (e.g. new key type was added or entries were stale).
	return bastionSync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).KnownHostsFromDB(&user)
}
