package session

import (
	"reflect"
	"testing"
)

func TestParseDBRequest(t *testing.T) {
	tests := []struct {
		name   string
		cmd    string
		args   []string
		want   []string
		wantOK bool
	}{
		{
			name:   "split command string",
			cmd:    "--db db-main.internal --mysql --dbname appdb",
			want:   []string{"db-main.internal", "--mysql", "--dbname", "appdb"},
			wantOK: true,
		},
		{
			name:   "separate args",
			cmd:    "--db",
			args:   []string{"dbuser@db-main.internal"},
			want:   []string{"dbuser@db-main.internal"},
			wantOK: true,
		},
		{
			name:   "short separate args",
			cmd:    "-db",
			args:   []string{"dbuser@db-main.internal"},
			want:   []string{"dbuser@db-main.internal"},
			wantOK: true,
		},
		{
			name:   "short split command string",
			cmd:    "-db db-main.internal --mysql --dbname appdb",
			want:   []string{"db-main.internal", "--mysql", "--dbname", "appdb"},
			wantOK: true,
		},
		{
			name:   "not a db request",
			cmd:    "deploy@host -p 22",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseDBRequest(tt.cmd, tt.args)
			if ok != tt.wantOK {
				t.Fatalf("parseDBRequest(%q, %v) ok = %t, want %t", tt.cmd, tt.args, ok, tt.wantOK)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseDBRequest(%q, %v) = %v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}
