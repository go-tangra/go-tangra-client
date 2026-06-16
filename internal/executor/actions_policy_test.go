package executor

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-actions/workflow"
)

func TestRestrictedRegistry_ExcludesShellAndScripts(t *testing.T) {
	reg := newRestrictedRegistry()

	if _, ok := reg.Get("run"); ok {
		t.Error("restricted registry must NOT include the shell `run` action")
	}
	for _, name := range []string{"package", "file", "file_line", "service", "service_status", "hostname", "timezone"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("restricted registry missing native action %q", name)
		}
	}
}

func TestValidateRestricted(t *testing.T) {
	reg := newRestrictedRegistry()

	cases := []struct {
		name    string
		yaml    string
		wantErr string // substring; "" means must pass
	}{
		{
			name: "native actions only passes",
			yaml: `
name: ok
jobs:
  main:
    steps:
      - uses: service_status
        with: { name: nginx }
      - uses: package
        with: { name: htop, state: present }
`,
		},
		{
			name: "run step rejected",
			yaml: `
name: shelly
jobs:
  main:
    steps:
      - name: do apt
        run: apt update
`,
			wantErr: "shell",
		},
		{
			name: "non-native uses rejected",
			yaml: `
name: scripted
jobs:
  main:
    steps:
      - id: fetch
        uses: my-js-action
        with: { url: http://x }
`,
			wantErr: "not permitted",
		},
		{
			name: "rejected even when a later job is clean",
			yaml: `
name: mixed
jobs:
  a:
    steps:
      - uses: service
        with: { name: nginx, state: started }
  b:
    steps:
      - run: rm -rf /tmp/x
`,
			wantErr: "shell",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, err := workflow.Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			gotErr := validateRestricted(wf, reg)
			if tc.wantErr == "" {
				if gotErr != nil {
					t.Fatalf("expected pass, got %v", gotErr)
				}
				return
			}
			if gotErr == nil || !strings.Contains(gotErr.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, gotErr)
			}
		})
	}
}
