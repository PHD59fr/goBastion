package piv

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const maxCertificateFileBytes = 64 << 10

// ReadCertificateFile bounds user-selected PEM input before it reaches a
// session process or the database. A held descriptor prevents a final symlink
// swap, and nonblocking open avoids waiting on a FIFO.
func ReadCertificateFile(path string) ([]byte, error) {
	invalid := errors.New("certificate must be a regular file of at most 64 KiB")
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, invalid
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCertificateFileBytes {
		return nil, invalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCertificateFileBytes+1))
	if err != nil || len(data) > maxCertificateFileBytes {
		return nil, invalid
	}
	return data, nil
}
