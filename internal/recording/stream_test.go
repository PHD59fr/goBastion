package recording

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type testStreamSink struct {
	bytes.Buffer
	flushErr error
	short    bool
	flushes  int
	onFlush  func()
}

type finalChunkAfterEOF struct {
	done  chan struct{}
	reads int
}

type endlessRawReader struct{ reads int }

func (r *endlessRawReader) Read(p []byte) (int, error) {
	r.reads++
	return copy(p, "still recording"), nil
}

func (r *finalChunkAfterEOF) Read(p []byte) (int, error) {
	r.reads++
	switch r.reads {
	case 1:
		close(r.done)
		return 0, io.EOF
	case 2:
		return copy(p, "final bytes"), nil
	default:
		return 0, io.EOF
	}
}

func (s *testStreamSink) Write(p []byte) (int, error) {
	if s.short {
		return len(p) - 1, nil
	}
	return s.Buffer.Write(p)
}

func (s *testStreamSink) Flush() error {
	s.flushes++
	if s.onFlush != nil {
		s.onFlush()
	}
	return s.flushErr
}

func TestStreamRawStopsClientWhenCaptureFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.ttyrec")
	if err := os.WriteFile(path, []byte("recorded bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name string
		sink testStreamSink
		want error
	}{
		{"flush", testStreamSink{flushErr: io.ErrClosedPipe}, io.ErrClosedPipe},
		{"short-write", testStreamSink{short: true}, io.ErrShortWrite},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			stopped := make(chan struct{})
			finished := make(chan error, 1)
			go func() {
				finished <- StreamRaw(path, &fixture.sink, make(chan struct{}), nil, func() { close(stopped) })
			}()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("capture failure did not stop the active client")
			}
			if err := <-finished; !errors.Is(err, fixture.want) {
				t.Fatalf("capture error = %v, want %v", err, fixture.want)
			}
		})
	}
}

func TestStreamRawRefusesMissingRecorderOutput(t *testing.T) {
	done := make(chan struct{})
	close(done)
	stopped := false
	err := StreamRaw(filepath.Join(t.TempDir(), "missing.ttyrec"), &testStreamSink{}, done, nil, func() { stopped = true })
	if err == nil || !strings.Contains(err.Error(), "without creating") || !stopped {
		t.Fatalf("missing capture err=%v stopped=%v", err, stopped)
	}
}

func TestStreamRawRejectsSymlinkAndNonregularSource(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "ordinary.ttyrec")
	if err := os.WriteFile(regular, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.ttyrec")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, dir} {
		stopped := false
		if err := StreamRaw(path, &testStreamSink{}, make(chan struct{}), nil, func() { stopped = true }); err == nil || !stopped {
			t.Fatalf("unsafe source %q accepted: err=%v stopped=%v", path, err, stopped)
		}
	}
}

func TestStreamRawDrainsAndFlushesCompletedRecording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.ttyrec")
	const data = "complete recording"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	close(done)
	sink := &testStreamSink{}
	if err := StreamRaw(path, sink, done, nil, func() { t.Fatal("successful capture stopped the client") }); err != nil {
		t.Fatal(err)
	}
	if sink.String() != data || sink.flushes != 1 {
		t.Fatalf("capture bytes=%q flushes=%d", sink.String(), sink.flushes)
	}
}

func TestStreamRawDrainsBytesAppendedAtRecorderExit(t *testing.T) {
	done := make(chan struct{})
	reader := &finalChunkAfterEOF{done: done}
	sink := &testStreamSink{}
	if err := streamOpenedRaw(reader, sink, done, nil, nil, func(err error) error { return err }); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "final bytes" || reader.reads != 3 {
		t.Fatalf("final capture bytes=%q reads=%d", sink.String(), reader.reads)
	}
}

func TestStreamRawFullSinkCancelsActiveClient(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("kernel full-device fixture unavailable: %v", err)
	}
	defer func() { _ = full.Close() }()
	path := filepath.Join(t.TempDir(), "session.ttyrec")
	if err := os.WriteFile(path, []byte("recorded bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := exec.CommandContext(ctx, "sleep", "10")
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- client.Wait() }()
	started := time.Now()
	err = StreamRaw(path, gzip.NewWriter(full), make(chan struct{}), nil, cancel)
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("full recording sink returned %v, want ENOSPC", err)
	}
	if ctx.Err() == nil {
		t.Fatal("client context remained active after recording volume filled")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("recording failure was detected after %v", elapsed)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("client exited successfully after recording volume filled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client continued after recording volume filled")
	}
}

func TestStreamRawAbortsWhenRecorderCompletionIsUncertain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.ttyrec")
	if err := os.WriteFile(path, []byte("partial recording"), 0600); err != nil {
		t.Fatal(err)
	}
	flushed := make(chan struct{})
	abort := make(chan struct{})
	stopped := make(chan struct{})
	sink := &testStreamSink{onFlush: func() { close(flushed) }}
	result := make(chan error, 1)
	go func() {
		result <- StreamRaw(path, sink, make(chan struct{}), abort, func() { close(stopped) })
	}()
	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Fatal("stream did not capture initial bytes")
	}
	close(abort)
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "aborted") {
			t.Fatalf("uncertain recorder completion was accepted: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream remained blocked after completion abort")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("completion abort did not request client stop")
	}
}

func TestStreamRawAbortsContinuallyGrowingRecording(t *testing.T) {
	abort := make(chan struct{})
	reader := &endlessRawReader{}
	sink := &testStreamSink{onFlush: func() { close(abort) }}
	err := streamOpenedRaw(reader, sink, make(chan struct{}), abort, nil, func(err error) error { return err })
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("growing recording ignored completion abort: %v", err)
	}
	if reader.reads != 1 {
		t.Fatalf("stream read %d blocks after abort, want one", reader.reads)
	}
}
