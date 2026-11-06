package dbsandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Allocate before entering the jail: its root deliberately exposes no devpts
// filesystem. Only the trusted worker receives the master descriptor.
func openClientTerminal(uid int) (*os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	master := os.NewFile(uintptr(fd), "client-terminal")
	fail := func(err error) (*os.File, error) { _ = master.Close(); return nil, err }
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return fail(err)
	}
	slave, err := terminalPeer(fd)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = slave.Close() }()
	if err := slave.Chown(uid, uid); err != nil {
		return fail(err)
	}
	if err := slave.Chmod(0600); err != nil {
		return fail(err)
	}
	return master, nil
}

// TIOCGPTPEER opens the slave through its master without exposing /dev/pts (or
// /proc/self/fd) inside the jail. The parent's slave copy is closed before exec.
func terminalPeer(masterFD int) (*os.File, error) {
	fd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(masterFD), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(fd, "client-tty"), nil
}

func runClient(cmd *exec.Cmd, master *os.File) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return cmd.Run()
	}
	slave, err := terminalPeer(int(master.Fd()))
	if err != nil {
		return fmt.Errorf("open client terminal: %w", err)
	}
	defer func() { _ = slave.Close() }()
	settings, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	if err != nil {
		return err
	}
	if err := unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, settings); err != nil {
		return err
	}
	// Keep Ctrl-C as a byte on the recorder/NsJail terminal. The client slave
	// converts it to SIGINT in the native client's own foreground group.
	state, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), state) }()
	var previous unix.Winsize
	resize := func() {
		size, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
		if err == nil && *size != previous {
			if unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, size) == nil {
				previous = *size
			}
		}
	}
	resize()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = slave.Close()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				resize()
			}
		}
	}()
	go func() { _, _ = io.Copy(master, os.Stdin) }()
	output := make(chan error, 1)
	go func() {
		err := copyTerminalOutput(master, os.Stdout, done)
		if err != nil {
			_ = cmd.Process.Kill()
		}
		output <- err
	}()
	clientErr := cmd.Wait()
	close(done)
	if outputErr := <-output; outputErr != nil {
		return fmt.Errorf("read client terminal: %w", outputErr)
	}
	return clientErr
}

func copyTerminalOutput(master *os.File, out io.Writer, done <-chan struct{}) error {
	buffer := make([]byte, 32*1024)
	for {
		fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, 100); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			select {
			case <-done:
				return nil // Client exited; all pending output has been drained.
			default:
				continue
			}
		}
		n, err := master.Read(buffer)
		if n > 0 {
			if _, writeErr := out.Write(buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if errors.Is(err, unix.EIO) || errors.Is(err, io.EOF) {
			return nil // Linux PTY masters return EIO when the last slave closes.
		}
		if err != nil {
			return err
		}
	}
}
