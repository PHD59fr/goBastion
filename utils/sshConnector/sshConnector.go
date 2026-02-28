package sshConnector

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"goBastion/models"

	"github.com/google/uuid"
)

// SshConnection writes the egress key to a temp file and executes an SSH session via ttyrec.
func SshConnection(user models.User, access models.AccessRight) error {
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
	defer func(outFile *os.File) {
		_ = outFile.Close()
	}(outFile)
	gzipWriter := gzip.NewWriter(outFile)
	defer func(gzipWriter *gzip.Writer) {
		_ = gzipWriter.Close()
	}(gzipWriter)

	done := make(chan error, 1)
	go func() {
		var f *os.File
		for {
			f, err = os.Open(ttyrecFile)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)

		buf := make([]byte, 4096)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				if _, werr := gzipWriter.Write(buf[:n]); werr != nil {
					done <- fmt.Errorf("gzip write error: %v", werr)
					return
				}
			}
			if err == io.EOF {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if err != nil {
				done <- fmt.Errorf("file read error: %v", err)
				return
			}
		}
	}()

	cmd := exec.Command(
		"ttyrec", "-f", ttyrecFile, "--",
		"ssh", "-i", tmpFilePath, access.Username+"@"+access.Server, "-p", strconv.FormatInt(access.Port, 10),
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Connecting ...")

	if err := cmd.Run(); err != nil {
		switch err.Error() {
		case "exit status 100", "exit status 130", "signal: interrupt":
			return nil
		}
		return fmt.Errorf("ttyrec execution error: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	_ = os.Remove(ttyrecFile)
	_ = gzipWriter.Close()
	_ = outFile.Close()

	return nil
}
