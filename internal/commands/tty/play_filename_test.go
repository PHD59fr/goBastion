package tty

import "testing"

func TestRecordingServer(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
		ok   bool
	}{
		{name: "hostname", file: "root.db.internal:22_2026-07-21_12-30-00.ttyrec.gz", want: "db.internal", ok: true},
		{name: "IPv6", file: "root.2001:db8::10:2222_2026-07-21_12-30-00.ttyrec.gz", want: "2001:db8::10", ok: true},
		{name: "command and session ID", file: "deploy.host_name:22_2026-07-21_12-30-00_cmd_sid-123e4567-e89b-12d3-a456-426614174000.ttyrec.gz", want: "host_name", ok: true},
		{name: "path traversal", file: "root...:22_2026-07-21_12-30-00.ttyrec.gz", ok: false},
		{name: "slash", file: "root.foo/bar:22_2026-07-21_12-30-00.ttyrec.gz", ok: false},
		{name: "missing port", file: "root.host_2026-07-21_12-30-00.ttyrec.gz", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := recordingServer(tt.file)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("recordingServer(%q) = (%q, %t), want (%q, %t)", tt.file, got, ok, tt.want, tt.ok)
			}
		})
	}
}
