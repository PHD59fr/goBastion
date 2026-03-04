package sshConnector

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"goBastion/models"
	bastionSync "goBastion/utils/sync"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SshConnection writes the egress key to a temp file and executes an SSH session via ttyrec.
// It performs TOFU host key verification before connecting.
func SshConnection(db *gorm.DB, user models.User, access models.AccessRight) error {
	if err := checkAndUpdateHostKey(db, user, access.Server, access.Port); err != nil {
		return err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting user home directory: %v", err)
	}
	tmpFilePath := filepath.Join(homeDir, ".tmp", fmt.Sprintf("sshkey-%s.pem", uuid.New().String()))

	if err = os.MkdirAll(filepath.Dir(tmpFilePath), 0700); err != nil {
		return fmt.Errorf("error creating ~/.tmp directory: %v", err)
	}
	privateKey := access.PrivateKey + "\n"
	if err = os.WriteFile(tmpFilePath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("error writing private key: %v", err)
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(tmpFilePath)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	dir := fmt.Sprintf("/app/ttyrec/%s/%s/", user.Username, access.Server)
	if err = os.MkdirAll(dir, 0777); err != nil {
		return fmt.Errorf("error creating ttyrec dir: %v", err)
	}

	ttyrecFile := fmt.Sprintf("%s%s.%s:%d_%s.ttyrec", dir, access.Username, access.Server, access.Port, timestamp)
	ttyrecGzFile := ttyrecFile + ".gz"

	outFile, err := os.Create(ttyrecGzFile)
	if err != nil {
		return fmt.Errorf("error creating gzip output file: %v", err)
	}
	gzipWriter := gzip.NewWriter(outFile)

	// Always remove the intermediate .ttyrec file on exit
	defer func() { _ = os.Remove(ttyrecFile) }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		var f *os.File
		for {
			f, err = os.Open(ttyrecFile)
			if err == nil {
				break
			}
			select {
			case <-ctx.Done():
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
					done <- fmt.Errorf("gzip write error: %v", werr)
					return
				}
			}
			if readErr == io.EOF {
				select {
				case <-ctx.Done():
					done <- nil
					return
				default:
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			if readErr != nil {
				done <- fmt.Errorf("file read error: %v", readErr)
				return
			}
		}
	}()

	knownHostsFile := fmt.Sprintf("/home/%s/.ssh/known_hosts", strings.ToLower(user.Username))
	cmd := exec.Command(
		"ttyrec", "-f", ttyrecFile, "--",
		"ssh", "-i", tmpFilePath,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+knownHostsFile,
		access.Username+"@"+access.Server, "-p", strconv.FormatInt(access.Port, 10),
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Connecting ...")

	cmdErr := cmd.Run()

	// Give the goroutine a moment to flush remaining bytes, then stop it
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	_ = gzipWriter.Close()
	_ = outFile.Close()

	if cmdErr != nil {
		switch cmdErr.Error() {
		case "exit status 100", "exit status 130", "signal: interrupt":
			return nil
		}
		return fmt.Errorf("ttyrec execution error: %v", cmdErr)
	}

	return nil
}

// checkAndUpdateHostKey implements TOFU (Trust On First Use) for the target server.
//   - First connection: the scanned key is stored in DB and trusted.
//   - Key unchanged: proceeds normally.
//   - Key changed: returns an error telling the user to run selfReplaceKnownHost.
func checkAndUpdateHostKey(db *gorm.DB, user models.User, server string, port int64) error {
	portStr := strconv.FormatInt(port, 10)
	out, err := exec.Command("ssh-keyscan", "-p", portStr, "-T", "5", server).Output()
	if err != nil || len(out) == 0 {
		// Can't scan (unreachable, firewall…) - let SSH fail naturally
		return nil
	}

	// Determine host token as stored in known_hosts
	var hostToken string
	if port == 22 {
		hostToken = server
	} else {
		hostToken = fmt.Sprintf("[%s]:%d", server, port)
	}

	// Parse scanned keys: keyType → full line
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

	// Fetch existing DB entries for this user
	var dbEntries []models.KnownHostsEntry
	db.Where("user_id = ?", user.ID).Find(&dbEntries)

	// Build map keyType → stored line for this specific host
	existing := make(map[string]string)
	for _, e := range dbEntries {
		parts := strings.Fields(e.Entry)
		if len(parts) >= 3 && parts[0] == hostToken {
			existing[parts[1]] = e.Entry
		}
	}

	// TOFU: nothing known for this host yet
	if len(existing) == 0 {
		for _, sk := range scanned {
			db.Create(&models.KnownHostsEntry{UserID: user.ID, Entry: sk.line})
		}
		return bastionSync.KnownHostsFromDB(db, &user)
	}

	// Check each scanned key against stored keys
	changed := false
	for _, sk := range scanned {
		storedLine, found := existing[sk.keyType]
		if found && storedLine != sk.line {
			changed = true
			break
		}
		if !found {
			// New key type added by the server - store it
			db.Create(&models.KnownHostsEntry{UserID: user.ID, Entry: sk.line})
		}
	}

	if changed {
		return fmt.Errorf(
			"WARNING: Host key verification failed for %s!\n"+
				"The remote host key has changed since the last connection.\n"+
				"If you trust the new key, run: selfReplaceKnownHost --host %s",
			server, server)
	}

	// Ensure file is up to date (e.g. new key type was added above)
	return bastionSync.KnownHostsFromDB(db, &user)
}

// CompressLegacyTtyrecFiles walks /app/ttyrec and compresses any bare .ttyrec file
// that does not already have a corresponding .ttyrec.gz, then removes the original.
// Safe to call only at startup before any session is active.
func CompressLegacyTtyrecFiles() error {
	const ttyrecRoot = "/app/ttyrec"
	if _, err := os.Stat(ttyrecRoot); os.IsNotExist(err) {
		return nil
	}
	return filepath.Walk(ttyrecRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		name := info.Name()
		// Only target plain .ttyrec (not .ttyrec.gz)
		if len(name) < 7 || name[len(name)-7:] != ".ttyrec" {
			return nil
		}
		gzPath := path + ".gz"
		// .gz already exists: just remove the plain file
		if _, statErr := os.Stat(gzPath); statErr == nil {
			return os.Remove(path)
		}
		// Compress then remove
		if compErr := compressFile(path, gzPath); compErr != nil {
			return compErr
		}
		return os.Remove(path)
	})
}

func compressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	gz := gzip.NewWriter(out)
	if _, err = io.Copy(gz, in); err != nil {
		_ = gz.Close()
		_ = os.Remove(dst)
		return err
	}
	return gz.Close()
}
