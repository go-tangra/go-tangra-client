package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-actions/engine"
	"github.com/go-tangra/go-tangra-actions/workflow"
)

func TestRestrictedRegistry_ExcludesShellAndScripts(t *testing.T) {
	reg := newRestrictedRegistry()

	if _, ok := reg.Get("run"); ok {
		t.Error("restricted registry must NOT include the shell `run` action")
	}
	for _, name := range []string{"package", "file", "file_line", "service", "service_status", "log", "hostname", "timezone"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("restricted registry missing native action %q", name)
		}
	}
}

// mustResolved parses an action manifest into a ResolvedAction for a test resolver.
func mustResolved(t *testing.T, manifest string) *engine.ResolvedAction {
	t.Helper()
	def, err := workflow.ParseAction([]byte(manifest))
	if err != nil {
		t.Fatalf("parse action: %v", err)
	}
	return &engine.ResolvedAction{Def: def}
}

func TestValidateRestricted(t *testing.T) {
	reg := newRestrictedRegistry()

	// A composite that uses only native actions (the allowed php-fpm example).
	nativeComposite := `
name: disable-old-php-fpm
description: x
runs:
  using: composite
  steps:
    - id: check_new
      uses: service_status
      with: { name: php8.4-fpm }
    - id: disable_old
      uses: service
      with: { name: php8.3-fpm, state: stopped, enabled: "false" }
`
	// A composite that runs bash internally (the forbidden php-fpm example / system-update shape).
	bashComposite := `
name: disable-old-php-fpm-bash
description: x
runs:
  using: composite
  steps:
    - id: check_new
      run: systemctl is-enabled php8.4-fpm.service
      shell: bash
    - id: disable_old
      uses: service
      with: { name: php8.3-fpm, state: stopped, enabled: "false" }
`
	scriptedAction := `
name: install-fzf
description: x
runs:
  using: javascript
  main: index.js
`
	// A composite that references another composite which runs bash (nested).
	nestedBad := `
name: outer
description: x
runs:
  using: composite
  steps:
    - id: inner
      uses: disable-old-php-fpm-bash
`
	resolver := engine.MapResolver{
		"disable-old-php-fpm":      mustResolved(t, nativeComposite),
		"disable-old-php-fpm-bash": mustResolved(t, bashComposite),
		"install-fzf":              mustResolved(t, scriptedAction),
		"outer":                    mustResolved(t, nestedBad),
	}

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
			name: "log action passes (code-free echo)",
			yaml: `
name: logok
jobs:
  main:
    steps:
      - name: Report
        if: always()
        uses: log
        with: { message: "done via ${{ steps.x.outputs.manager }}" }
`,
		},
		{
			name: "composite of native actions passes",
			yaml: `
name: ok2
jobs:
  main:
    steps:
      - uses: disable-old-php-fpm
`,
		},
		{
			name: "top-level run step rejected",
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
			name: "composite with internal bash rejected",
			yaml: `
name: viacomposite
jobs:
  main:
    steps:
      - uses: disable-old-php-fpm-bash
`,
			wantErr: "shell",
		},
		{
			name: "scripted action rejected",
			yaml: `
name: scripted
jobs:
  main:
    steps:
      - uses: install-fzf
`,
			wantErr: "script",
		},
		{
			name: "nested composite with bash rejected",
			yaml: `
name: nested
jobs:
  main:
    steps:
      - uses: outer
`,
			wantErr: "shell",
		},
		{
			name: "unresolvable action rejected (fail closed)",
			yaml: `
name: unknown
jobs:
  main:
    steps:
      - uses: does-not-exist
`,
			wantErr: "could not be resolved",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wf, err := workflow.Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			gotErr := validateRestricted(context.Background(), wf, reg, resolver)
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
