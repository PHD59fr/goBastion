// Package dbsandbox launches fixed DB clients in per-session NsJail namespaces.
package dbsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Spec struct {
	Binary        string
	Args, Env     []string
	IP            string
	Port          int64
	TrackActivity bool
}

// Command never accepts sandbox settings or executables from the user.
func Command(ctx context.Context, host string, port int64, bin string, args, env []string) (*exec.Cmd, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, fmt.Errorf("DB clients require the privileged sandbox supervisor")
	}
	if bin != "psql" && bin != "mariadb" && bin != "redis-cli" {
		return nil, nil, fmt.Errorf("unsupported DB client")
	}
	if err := os.MkdirAll("/run/gobastion-db", 0711); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod("/run/gobastion-db", 0711); err != nil {
		return nil, nil, err
	}
	var dir string
	uid := 100000
	for ; uid < 104096; uid++ {
		// Never terminate an existing OS account when cleaning up a jail UID.
		if _, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			continue
		} else {
			var missing user.UnknownUserIdError
			if !errors.As(err, &missing) {
				return nil, nil, fmt.Errorf("check sandbox UID: %w", err)
			}
		}
		dir = filepath.Join("/run/gobastion-db", strconv.Itoa(uid))
		if err := os.Mkdir(dir, 0700); err == nil {
			break
		} else if !errors.Is(err, os.ErrExist) {
			return nil, nil, err
		}
	}
	if uid == 104096 {
		return nil, nil, fmt.Errorf("no sandbox slot available")
	}
	ctx, cancel := context.WithCancel(ctx)
	cleanupDir := func() { cancel(); _ = os.RemoveAll(dir) }
	first, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.FormatInt(port, 10)), 5*time.Second)
	if err != nil {
		cleanupDir()
		return nil, nil, err
	}
	ip := first.RemoteAddr().(*net.TCPAddr).IP.String()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = first.Close()
		cleanupDir()
		return nil, nil, err
	}
	// Let Go's poller interrupt the supervisor's Read when the session is
	// canceled. Closing a descriptor in another thread does not interrupt a
	// blocking Linux recv; it can otherwise retain the worker's liveness socket.
	if err := unix.SetNonblock(pair[0], true); err != nil {
		_ = unix.Close(pair[0])
		_ = unix.Close(pair[1])
		_ = first.Close()
		cleanupDir()
		return nil, nil, err
	}
	parent := os.NewFile(uintptr(pair[0]), "broker")
	child := os.NewFile(uintptr(pair[1]), "relay")
	r, w, err := os.Pipe()
	if err != nil {
		_ = parent.Close()
		_ = child.Close()
		_ = first.Close()
		cleanupDir()
		return nil, nil, err
	}
	hosts := filepath.Join(dir, "hosts")
	err = os.WriteFile(hosts, []byte(ip+" "+host+"\n127.0.0.1 localhost\n::1 localhost\n"), 0644)
	if err == nil {
		// The supervisor inherits a restrictive umask (0007 in production).
		// The mapped client UID must still read this root-owned hosts file.
		err = os.Chmod(hosts, 0644)
	}
	if err != nil {
		_ = parent.Close()
		_ = child.Close()
		_ = r.Close()
		_ = w.Close()
		_ = first.Close()
		cleanupDir()
		return nil, nil, err
	}
	// NsJail resolves bind sources after mapping the session UID. The parent
	// permits traversal, while this directory is readable only by that reserved
	// UID. It contains only the root-owned, read-only hosts mapping.
	if err = os.Chown(dir, uid, uid); err == nil {
		err = os.Chmod(dir, 0500)
	}
	if err != nil {
		_ = parent.Close()
		_ = child.Close()
		_ = r.Close()
		_ = w.Close()
		_ = first.Close()
		cleanupDir()
		return nil, nil, err
	}
	terminal, err := openClientTerminal(uid)
	if err != nil {
		_ = parent.Close()
		_ = child.Close()
		_ = r.Close()
		_ = w.Close()
		_ = first.Close()
		cleanupDir()
		return nil, nil, fmt.Errorf("allocate client terminal: %w", err)
	}
	jailArgs := []string{"--mode", "o", "--quiet", "--chroot", "/opt/gobastion-db-root", "--user", "0:" + strconv.Itoa(uid) + ":1", "--group", "0:" + strconv.Itoa(uid) + ":1", "--cap", "CAP_NET_ADMIN", "--cap", "CAP_SETPCAP", "--disable_clone_newcgroup", "--disable_proc", "--time_limit", "0", "--rlimit_as", "2048", "--rlimit_nproc", "32", "--rlimit_nofile", "128", "--rlimit_fsize", "64", "--tmpfsmount", "/tmp", "--tmpfsmount", "/home", "--bindmount_ro", hosts + ":/etc/hosts", "--bindmount_ro", "/dev/null:/dev/null", "--bindmount_ro", "/dev/urandom:/dev/urandom", "--bindmount_ro", "/dev/zero:/dev/zero", "--seccomp_string", sandboxPolicy(), "--pass_fd", "3", "--pass_fd", "4", "--pass_fd", "5", "--", "/bin/db-worker"}
	// NsJail shares its staging directory names across mapped UIDs. Give only
	// this child the umask it expects so another session can traverse them.
	// The script is constant; arguments are passed as quoted positional values.
	launcher := append([]string{"-c", `umask 022; exec /usr/local/sbin/nsjail "$@"`, "gobastion-db-jail"}, jailArgs...)
	cmd := exec.CommandContext(ctx, "/bin/sh", launcher...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.ExtraFiles = []*os.File{child, r, terminal}
	cmd.Cancel = func() error {
		_ = exec.Command("/usr/bin/pkill", "-KILL", "-u", strconv.Itoa(uid)).Run()
		return cmd.Process.Kill()
	}
	// Keep the SSH terminal's foreground process group. ConnectContext also
	// applies these attributes to ttyrec, whose terminal setup would otherwise
	// receive SIGTTOU in a new background group. Cleanup uses the reserved UID
	// and broker lifetime, rather than a process-group signal.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	var once sync.Once
	clean := func() {
		once.Do(func() {
			cancel()
			_ = exec.Command("/usr/bin/pkill", "-KILL", "-u", strconv.Itoa(uid)).Run()
			_ = parent.Close()
			_ = child.Close()
			_ = r.Close()
			_ = w.Close()
			_ = terminal.Close()
			_ = first.Close()
			cleanupDir()
		})
	}
	auth, clientArgs, clientEnv := newBroker(ctx, host, net.JoinHostPort(ip, strconv.FormatInt(port, 10)), bin, args, env, first)
	auth.touch, _ = ctx.Value(activityKey{}).(func())
	go func() {
		defer func() { _ = w.Close() }()
		_ = json.NewEncoder(w).Encode(Spec{Binary: bin, Args: clientArgs, Env: clientEnv, IP: ip, Port: port, TrackActivity: auth.touch != nil})
	}()
	go auth.serve(parent)
	return cmd, clean, nil
}

// Worker runs only inside the jail. It cannot name a destination in the broker protocol.
func Worker() error {
	// Capability and no-new-privileges changes apply to the calling OS thread.
	// Keep the native client's fork on that thread after dropping privileges.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	unix.CloseOnExec(5)
	terminal := os.NewFile(5, "client-terminal")
	defer func() { _ = terminal.Close() }()
	config := os.NewFile(4, "config")
	defer func() { _ = config.Close() }()
	var spec Spec
	if err := json.NewDecoder(io.LimitReader(config, 65536)).Decode(&spec); err != nil {
		return err
	}
	if spec.Binary != "psql" && spec.Binary != "mariadb" && spec.Binary != "redis-cli" {
		return fmt.Errorf("invalid worker executable")
	}
	ip := net.ParseIP(spec.IP)
	if ip == nil {
		return fmt.Errorf("invalid pinned address")
	}
	if !ip.IsLoopback() {
		prefix := "/32"
		if ip.To4() == nil {
			prefix = "/128"
		}
		if out, err := exec.Command("/sbin/ip", "addr", "add", ip.String()+prefix, "dev", "lo").CombinedOutput(); err != nil {
			return fmt.Errorf("configure loopback: %s: %w", out, err)
		}
	}
	// Drop every capability from the bounding and effective sets before accepting input.
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return err
		}
	}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &data[0]); err != nil {
		return err
	}
	// Keep native client shells from reading or modifying the relay process via
	// /proc/1/mem (same UID is insufficient when the process is not dumpable).
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), strconv.FormatInt(spec.Port, 10)))
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	// A killed controller cannot run deferred cleanup. The private broker socket
	// is its liveness channel: PID 1 exiting tears down every client descendant.
	go func() {
		poll := []unix.PollFd{{Fd: 3, Events: unix.POLLHUP | unix.POLLRDHUP}}
		for {
			if _, err := unix.Poll(poll, -1); err == unix.EINTR {
				continue
			} else if err != nil {
				os.Exit(1)
			}
			if poll[0].Revents&(unix.POLLHUP|unix.POLLRDHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				os.Exit(1)
			}
		}
	}()
	control := os.NewFile(3, "relay")
	var mu sync.Mutex
	go func() {
		for {
			local, e := listener.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			_, e = control.Write([]byte{1})
			var remote net.Conn
			if e == nil {
				b := make([]byte, 1)
				oob := make([]byte, unix.CmsgSpace(4))
				_, n, _, _, re := unix.Recvmsg(int(control.Fd()), b, oob, unix.MSG_CMSG_CLOEXEC)
				e = re
				if e == nil {
					msgs, re := unix.ParseSocketControlMessage(oob[:n])
					e = re
					if e == nil && len(msgs) == 1 {
						fds, re := unix.ParseUnixRights(&msgs[0])
						e = re
						if e == nil && len(fds) == 1 {
							f := os.NewFile(uintptr(fds[0]), "target")
							remote, e = net.FileConn(f)
							_ = f.Close()
						}
					}
				}
			}
			mu.Unlock()
			if e != nil || remote == nil {
				_ = local.Close()
				continue
			}
			go func() {
				defer func() { _ = local.Close(); _ = remote.Close() }()
				go func() {
					_, _ = io.Copy(remote, local)
					if c, ok := remote.(interface{ CloseWrite() error }); ok {
						_ = c.CloseWrite()
					}
				}()
				_, _ = io.Copy(local, remote)
			}()
		}
	}()
	cmd := exec.Command("/usr/bin/"+spec.Binary, spec.Args...)
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=/home", "LANG=C.UTF-8"}, spec.Env...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	var touch func()
	if spec.TrackActivity {
		touch = activityNotifier(int(control.Fd()))
	}
	return runClient(cmd, terminal, touch)
}

// Use architecture-specific syscall numbers: Kafel 3.4 names differ from Linux names.
func sandboxPolicy() string {
	calls := []int{unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_BPF, unix.SYS_KEYCTL, unix.SYS_PERF_EVENT_OPEN, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_IO_URING_SETUP, unix.SYS_PIDFD_GETFD}
	rules := make([]string, len(calls))
	for i, n := range calls {
		rules[i] = fmt.Sprintf("SYSCALL[%d]", n)
	}
	namespaceFlags := uint64(unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWNET | unix.CLONE_NEWPID | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWTIME)
	// The network namespace does not isolate AF_VSOCK/AF_ALG. Restrict address
	// families as well as routes; NETLINK is needed only for worker loopback setup.
	rules = append(rules, fmt.Sprintf("SYSCALL[%d](domain, type, protocol) { domain != %d && domain != %d && domain != %d && domain != %d }", unix.SYS_SOCKET, unix.AF_UNIX, unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK))
	rules = append(rules, fmt.Sprintf("SYSCALL[%d](flags, stack, parent_tid, child_tid, tls) { (flags & %d) != 0 }", unix.SYS_CLONE, namespaceFlags))
	return "POLICY blocked { ERRNO(1) { " + strings.Join(rules, ", ") + fmt.Sprintf(" }, ERRNO(38) { SYSCALL[%d] } } USE blocked DEFAULT ALLOW", unix.SYS_CLONE3)
}
