package dbsandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Pipes cannot detect job-control stops. Give the supervisor its own controlling
// terminal, then launch ttyrec with the same attributes used by ConnectContext.
func TestRecordingWithControllingTerminal(t *testing.T) {
	if os.Getenv("GOB_SANDBOX_INTEGRATION") != "1" {
		t.Skip("requires the isolation-test Docker target")
	}
	for _, scenario := range []string{"psql", "mariadb", "keyboard", "keyboard-mariadb", "keyboard-direct", "terminate", "hangup", "interrupt"} {
		t.Run(scenario, func(t *testing.T) {
			masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			master := os.NewFile(uintptr(masterFD), "pty-master")
			defer func() { _ = master.Close() }()
			if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
				t.Fatal(err)
			}
			number, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
			if err != nil {
				t.Fatal(err)
			}
			slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|unix.O_NOCTTY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = slave.Close() }()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run", "^TestRecordingTerminalHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "GOB_TERMINAL_HELPER="+scenario, "GOB_TERMINAL_RECORDING="+filepath.Join(t.TempDir(), "session.ttyrec"))
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = slave.Close()
			done := make(chan struct{})
			var waitErr error
			go func() { waitErr = cmd.Wait(); close(done) }()
			defer func() { cancel(); <-done }()
			var output strings.Builder
			readUntil := func(marker string) {
				t.Helper()
				for !strings.Contains(output.String(), marker) {
					if ctx.Err() != nil {
						t.Fatalf("waiting for %q: %v\n%s", marker, ctx.Err(), output.String())
					}
					poll := []unix.PollFd{{Fd: int32(masterFD), Events: unix.POLLIN}}
					if _, err := unix.Poll(poll, 100); err != nil && err != unix.EINTR {
						t.Fatal(err)
					}
					if poll[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
						continue
					}
					buf := make([]byte, 4096)
					n, err := unix.Read(masterFD, buf)
					if n > 0 {
						_, _ = output.Write(buf[:n])
					}
					if err != nil || n == 0 {
						t.Fatalf("terminal closed before %q: %v\n%s", marker, err, output.String())
					}
				}
			}
			write := func(input string) {
				t.Helper()
				if _, err := master.WriteString(input); err != nil {
					t.Fatal(err)
				}
			}
			readUntil("READY> ")
			query := "SELECT 'TERMINAL_' || 'RESULT';\n"
			mysql := strings.Contains(scenario, "mariadb")
			if mysql {
				query = "SELECT CONCAT('TERMINAL_', 'RESULT');\n"
			}
			write(query)
			readUntil("TERMINAL_RESULT") // Cannot be satisfied by input echo.
			if scenario == "psql" {
				write("\\! GOB_CHECK_CLIENT_CAPS=1 /bin/caps-test -test.run TestNativeCapabilities -test.v\n")
				readUntil("CAPABILITIES_EMPTY")
			}
			if scenario != "psql" && scenario != "mariadb" {
				query := "SELECT pg_sleep(60) /* terminal_interrupt */;\n"
				if mysql {
					query = "SELECT SLEEP(60) /* terminal_interrupt */;\n"
				}
				write(query)
				// Wait for server-side execution, so an early Ctrl-C cannot merely
				// clear input that the native client has not submitted yet.
				for {
					probe := exec.CommandContext(ctx, "psql", "-XAt", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", "-d", "postgres", "-c", "SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND query LIKE 'SELECT pg_sleep(60) /* terminal_interrupt */%'")
					if mysql {
						probe = exec.CommandContext(ctx, "mariadb", "--batch", "--skip-column-names", "--protocol=tcp", "-h", "127.0.0.1", "-P", "53306", "-u", "root", "-e", "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE INFO LIKE 'SELECT SLEEP(60)%'")
					}
					out, err := probe.Output()
					if err != nil {
						t.Fatalf("query execution probe: %v: %s", err, out)
					}
					if strings.TrimSpace(string(out)) == "1" {
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			if strings.HasPrefix(scenario, "keyboard") {
				write("\x03")
				message, nextQuery := "canceling statement due to user request", "SELECT 'AFTER_' || 'INTERRUPT';\n"
				if mysql {
					message, nextQuery = "Query execution was interrupted", "SELECT CONCAT('AFTER_', 'INTERRUPT');\n"
				}
				readUntil(message)
				write(nextQuery)
				readUntil("AFTER_INTERRUPT")
				if !mysql {
					if err := unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, &unix.Winsize{Row: 37, Col: 91}); err != nil {
						t.Fatal(err)
					}
					// BusyBox stty honors the shell's stale LINES/COLUMNS before
					// consulting the terminal. Inspect the kernel dimensions.
					write("\\! for i in $(seq 1 50); do size=$(unset LINES COLUMNS; stty size); if [ \"$size\" = \"37 91\" ]; then echo \"RESIZE_${size}\"; break; fi; sleep .05; done\n")
					readUntil("RESIZE_37 91")
				}
				write("\\q\n")
			} else if sig, ok := map[string]syscall.Signal{"terminate": syscall.SIGTERM, "hangup": syscall.SIGHUP, "interrupt": syscall.SIGINT}[scenario]; ok {
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
			} else {
				write("\\q\n")
			}
			readUntil("TERMINAL_CLEANUP_OK")
			<-done
			if waitErr != nil {
				t.Fatalf("terminal helper: %v\n%s", waitErr, output.String())
			}
		})
	}
}

func TestRecordingTerminalHelper(t *testing.T) {
	scenario := os.Getenv("GOB_TERMINAL_HELPER")
	if scenario == "" {
		t.Skip("controlling terminal helper")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 10*time.Second)
	defer timeout()
	binary, port := "psql", int64(55432)
	args := []string{"-X", "-v", "ON_ERROR_STOP=1", "-v", "PROMPT1=READY> ", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", "-d", "postgres"}
	if strings.Contains(scenario, "mariadb") {
		binary, port = "mariadb", 53306
		args = []string{"--protocol=tcp", "--prompt=READY> ", "-h", "127.0.0.1", "-P", "53306", "-u", "root"}
	}
	sandbox, clean, err := Command(ctx, "127.0.0.1", port, binary, args, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clean()
	var uid string
	for i, arg := range sandbox.Args {
		if arg == "--user" {
			uid = strings.Split(sandbox.Args[i+1], ":")[1]
			break
		}
	}
	if uid == "" {
		t.Fatal("missing reserved sandbox UID")
	}
	recording := os.Getenv("GOB_TERMINAL_RECORDING")
	args = append([]string{"-f", recording, "--", sandbox.Path}, sandbox.Args[1:]...)
	cmd := exec.CommandContext(ctx, "/usr/local/bin/ttyrec", args...)
	cmd.Env, cmd.ExtraFiles, cmd.SysProcAttr = sandbox.Env, sandbox.ExtraFiles, sandbox.SysProcAttr
	if strings.HasSuffix(scenario, "-direct") {
		cmd = sandbox
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	if scenario == "terminate" || scenario == "hangup" || scenario == "interrupt" {
		if err == nil || ctx.Err() != context.Canceled {
			t.Fatalf("expected cancellation: client=%v context=%v", err, ctx.Err())
		}
	} else if err != nil {
		t.Fatal(err)
	}
	clean()
	if !strings.HasSuffix(scenario, "-direct") {
		content, err := os.ReadFile(recording)
		if err != nil || !strings.Contains(string(content), "TERMINAL_RESULT") || (strings.HasPrefix(scenario, "keyboard") && !strings.Contains(string(content), "AFTER_INTERRUPT")) {
			t.Fatalf("recorded query result missing: %v\n%s", err, content)
		}
	}
	if _, err := os.Stat(filepath.Join("/run/gobastion-db", uid)); !os.IsNotExist(err) {
		t.Fatalf("sandbox directory left behind: %v", err)
	}
	// Cleanup must not rely on a separate process group: clients use a reserved
	// UID, and closing the broker also tears down the worker's PID namespace.
	deadline := time.Now().Add(2 * time.Second)
	for {
		output, err := exec.Command("/usr/bin/pgrep", "-u", uid).CombinedOutput()
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox processes left behind: %v\n%s", err, output)
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Println("TERMINAL_CLEANUP_OK")
}
