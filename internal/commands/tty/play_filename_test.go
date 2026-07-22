package tty

import "testing"

func TestValidRecordingName(t *testing.T) {
	tests := []struct {
		name string
		file string
		ok   bool
	}{
		{name: "hostname", file: "root.db.internal:22_2026-07-21_12-30-00.ttyrec.gz", ok: true},
		{name: "username with dot", file: "john.doe.db.internal:22_2026-07-21_12-30-00.ttyrec.gz", ok: true},
		{name: "IPv6", file: "root.2001:db8::10:2222_2026-07-21_12-30-00.ttyrec.gz", ok: true},
		{name: "command and session ID", file: "deploy.host_name:22_2026-07-21_12-30-00_cmd_sid-123e4567-e89b-12d3-a456-426614174000.ttyrec.gz", ok: true},
		{name: "database recording", file: "app.db-prod.internal:5432_2026-07-21_12-30-00_postgres_inventory_sid-123e4567-e89b-12d3-a456-426614174000.ttyrec.gz", ok: true},
		{name: "database name with underscore", file: "app.db-prod.internal:5432_2026-07-21_12-30-00_postgres_my_app_sid-123e4567-e89b-12d3-a456-426614174000.ttyrec.gz", ok: true},
		{name: "path traversal", file: "root...:22_2026-07-21_12-30-00.ttyrec.gz", ok: false},
		{name: "slash", file: "root.foo/bar:22_2026-07-21_12-30-00.ttyrec.gz", ok: false},
		{name: "missing port", file: "root.host_2026-07-21_12-30-00.ttyrec.gz", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validRecordingName(tt.file); got != tt.ok {
				t.Fatalf("validRecordingName(%q) = %t, want %t", tt.file, got, tt.ok)
			}
		})
	}
}

func TestRecordingLabel(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{name: "ssh", file: "root.db.internal:22_2026-07-21_12-30-00.ttyrec.gz", want: "SSH"},
		{name: "ssh cmd", file: "deploy.host_name:22_2026-07-21_12-30-00_cmd_sid-123e4567-e89b-12d3-a456-426614174000.ttyrec.gz", want: "SSH"},
		{name: "db postgres", file: "app.db-prod.internal:5432_2026-07-21_12-30-00_postgres_inventory_sid-123e4567-e89b-12d3-a456-426614174000.ttyrec.gz", want: "DB/postgres"},
		{name: "db redis", file: "root.redis-cache.internal:6379_2026-07-21_12-30-00_redis_sid-123e4567-e89b-12d3-a456-426614174000.ttyrec.gz", want: "DB/redis"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := recordingLabel(tt.file); got != tt.want {
				t.Fatalf("recordingLabel(%q) = %q, want %q", tt.file, got, tt.want)
			}
		})
	}
}
