package invagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The real v4.5.1 release manifest verifies with the built-in key.
func TestRealReleaseVerifies(t *testing.T) {
	keys, err := ParseKeyring(DefaultReleaseKeys)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := os.ReadFile("testdata/agent-release.json")
	sig, _ := os.ReadFile("testdata/agent-release.json.sig")
	m, err := keys.Verify(manifest, sig)
	if err != nil {
		t.Fatalf("v4.5.1 manifest: %v", err)
	}
	a, err := m.Select("linux", "amd64", "deb")
	if err != nil || m.Version != "4.5.1" || a.File != "tangra-inventory-agent_4.5.1_amd64.deb" || a.Size != 7051234 {
		t.Fatalf("manifest %+v %+v %v", m, a, err)
	}
	if _, err := m.Select("linux", "riscv64", "deb"); !errors.Is(err, ErrPlatform) {
		t.Fatal("unknown platform selected")
	}
	tampered := []byte(strings.Replace(string(manifest), "7051234", "7051235", 1))
	if _, err := keys.Verify(tampered, sig); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered manifest: %v", err)
	}
	other, _ := ParseKeyring("other:" + base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if _, err := other.Verify(manifest, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
}

func TestParseKeyring(t *testing.T) {
	for _, bad := range []string{"", "nocolon", "BAD:AAAA", "k:not-base64!", "k:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseKeyring(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// ---- a fake GitHub release served by httptest ----

type fakeRelease struct {
	priv  ed25519.PrivateKey
	keys  string
	pkg   []byte
	tag   string
	hits  map[string]int
	mu    sync.Mutex
	bad   bool // serve a package that does not match the manifest
	srv   *httptest.Server
	extra map[string]any
}

func newFakeRelease(t *testing.T, version string) *fakeRelease {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeRelease{priv: priv, keys: "test-key:" + base64.StdEncoding.EncodeToString(pub), pkg: []byte("deb package " + version), tag: "v" + version, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRelease) manifest() []byte {
	sum := sha256.Sum256(f.pkg)
	m := Manifest{Schema: 1, Version: strings.TrimPrefix(f.tag, "v"), CreatedAt: "2026-09-30T00:00:00Z", KeyID: "test-key", Artifacts: []Artifact{
		{OS: "linux", Arch: "amd64", InstallType: "deb", File: "agent.deb", Size: int64(len(f.pkg)), SHA256: hex.EncodeToString(sum[:])},
		{OS: "linux", Arch: "amd64", InstallType: "rpm", File: "agent.rpm", Size: int64(len(f.pkg)), SHA256: hex.EncodeToString(sum[:])},
	}}
	b, _ := json.MarshalIndent(m, "", "  ")
	return b
}

func (f *fakeRelease) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.mu.Unlock()
	base := f.srv.URL
	switch r.URL.Path {
	case "/repo/releases/latest", "/repo/releases/tags/" + f.tag:
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": f.tag, "assets": []map[string]string{
			{"name": manifestFile, "browser_download_url": base + "/dl/manifest"},
			{"name": signatureFile, "browser_download_url": base + "/dl/sig"},
			{"name": "agent.deb", "browser_download_url": base + "/dl/pkg"},
			{"name": "agent.rpm", "browser_download_url": base + "/dl/pkg"},
		}})
	case "/dl/manifest":
		_, _ = w.Write(f.manifest())
	case "/dl/sig":
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, f.manifest()))))
	case "/dl/pkg":
		if f.bad {
			_, _ = w.Write([]byte(strings.Repeat("x", len(f.pkg))))
			return
		}
		_, _ = w.Write(f.pkg)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeRelease) source() Source { return Source{HTTP: f.srv.Client(), API: f.srv.URL + "/repo"} }

func TestSourceDownloadVerifies(t *testing.T) {
	f := newFakeRelease(t, "4.5.2")
	keys, _ := ParseKeyring(f.keys)
	ctx := context.Background()
	src := f.source()
	rel, err := src.Release(ctx, "4.5.2")
	if err != nil {
		t.Fatal(err)
	}
	m, err := src.Manifest(ctx, rel, keys)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := m.Select("linux", "amd64", "deb")
	path := filepath.Join(t.TempDir(), "agent.deb")
	if err := src.Download(ctx, rel, a, path); err != nil {
		t.Fatal(err)
	}
	f.bad = true
	if err := src.Download(ctx, rel, a, path); !errors.Is(err, ErrArtifact) || exists(path) {
		t.Fatalf("tampered package: %v (file kept: %v)", err, exists(path))
	}
	if _, err := src.Release(ctx, "9.9.9"); err == nil {
		t.Fatal("missing release found")
	}
	if _, err := src.Manifest(ctx, Release{Tag: "v1.0.0", Assets: map[string]string{}}, keys); err == nil {
		t.Fatal("release without manifest accepted")
	}
	// A manifest of another version than its release is refused.
	rel.Tag = "v4.5.3"
	if _, err := src.Manifest(ctx, rel, keys); !errors.Is(err, ErrManifest) {
		t.Fatalf("version mismatch: %v", err)
	}
}

// ---- Configure ----

func TestConfigurePackagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	raw, _ := os.ReadFile("testdata/agent.yaml")
	_ = os.WriteFile(path, raw, 0o644)
	s := AgentSettings{Ingest: "portal.example.org:9977", KeyID: "ak_0123456789abcdef01234567", KeyFile: "/etc/inventory-agent/auto-enroll.key", CAFile: "/etc/inventory-agent/ca.pem"}
	changed, err := Configure(path, s)
	if err != nil || !changed {
		t.Fatalf("configure %v %v", changed, err)
	}
	out, _ := os.ReadFile(path)
	text := string(out)
	for _, want := range []string{"ingest_endpoint: portal.example.org:9977", "key_id: ak_0123456789abcdef01234567", "key_file: /etc/inventory-agent/auto-enroll.key",
		"ca_file: /etc/inventory-agent/ca.pem", "collect_disks: true", "# go-tangra inventory agent", "token_file: /etc/inventory-agent/enrollment.token"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if changed, err := Configure(path, s); err != nil || changed {
		t.Fatalf("second run changed the file: %v %v", changed, err)
	}
	s2 := s
	s2.Ingest = "other.example.org:9977"
	if _, err := Configure(path, s2); !errors.Is(err, ErrForeignConfig) {
		t.Fatalf("foreign endpoint: %v", err)
	}
}

func TestConfigureNewAndBadFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "agent.yaml")
	if _, err := Configure(path, AgentSettings{Ingest: "h:1", KeyID: "ak_0123456789abcdef01234567", KeyFile: "/k", ServerName: "h"}); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	for _, want := range []string{"ingest_endpoint: h:1", "credential_file: /var/lib/inventory-agent/credential", "state_file:", "server_name: h"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	bad := filepath.Join(dir, "bad.yaml")
	_ = os.WriteFile(bad, []byte("- a list\n"), 0o644)
	if _, err := Configure(bad, AgentSettings{Ingest: "h:1"}); err == nil {
		t.Fatal("list accepted")
	}
	_ = os.WriteFile(bad, []byte("a: [\n"), 0o644)
	if _, err := Configure(bad, AgentSettings{Ingest: "h:1"}); err == nil {
		t.Fatal("broken YAML accepted")
	}
}

// ---- Ensure ----

type fakeSys struct {
	mu        sync.Mutex
	root      bool
	pkgTool   string // dpkg | rpm | ""
	installed string // installed package version ("" none)
	calls     []string
	onRestart func()
	failCmd   string
}

func (s *fakeSys) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := name + " " + strings.Join(args, " ")
	s.calls = append(s.calls, call)
	if s.failCmd != "" && strings.HasPrefix(call, s.failCmd) {
		return []byte("boom"), errors.New("exit status 1")
	}
	switch name {
	case "dpkg-query":
		if s.installed == "" {
			return []byte("dpkg-query: no packages found"), errors.New("exit status 1")
		}
		return []byte("install ok installed|" + s.installed + "-1"), nil
	case "rpm":
		if args[0] == "-q" {
			if s.installed == "" {
				return []byte("package not installed"), errors.New("exit status 1")
			}
			return []byte(s.installed), nil
		}
		s.installed = "4.5.2"
	case "dpkg":
		s.installed = "4.5.2"
	case "systemctl":
		if args[0] == "restart" && s.onRestart != nil {
			s.onRestart()
		}
	}
	return nil, nil
}

func (s *fakeSys) LookPath(name string) (string, error) {
	if name == s.pkgTool {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (s *fakeSys) Geteuid() int {
	if s.root {
		return 0
	}
	return 1000
}

func (s *fakeSys) ran(prefix string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

type fx struct {
	in   *Installer
	sys  *fakeSys
	rel  *fakeRelease
	dir  string
	set  Settings
	logs []string
}

func newEnsureFx(t *testing.T) *fx {
	t.Helper()
	dir := t.TempDir()
	f := &fx{sys: &fakeSys{root: true, pkgTool: "dpkg"}, rel: newFakeRelease(t, "4.5.2"), dir: dir}
	f.in = &Installer{Sys: f.sys, Src: f.rel.source(), Arch: "amd64", Wait: 200 * time.Millisecond, Poll: 10 * time.Millisecond,
		Paths: Paths{Binary: filepath.Join(dir, "usr/bin/inventory-agent"), Config: filepath.Join(dir, "etc/agent.yaml"), KeyFile: filepath.Join(dir, "etc/auto-enroll.key"),
			Credential: filepath.Join(dir, "var/credential"), CAFile: filepath.Join(dir, "etc/ingest-ca.pem"), TempDir: dir},
		Logf: func(format string, a ...any) { f.logs = append(f.logs, fmt.Sprintf(format, a...)) }}
	f.set = Settings{Ingest: "portal.example.org:9977", KeyID: "ak_0123456789abcdef01234567", Key: "aks_secret", ReleaseKeys: f.rel.keys}
	// The agent stores its credential when it is restarted (it enrolled).
	f.sys.onRestart = func() {
		_ = os.MkdirAll(filepath.Dir(f.in.Paths.Credential), 0o700)
		_ = os.WriteFile(f.in.Paths.Credential, []byte("cred"), 0o600)
	}
	return f
}

func TestEnsureInstallsAndEnrolls(t *testing.T) {
	f := newEnsureFx(t)
	out, err := f.in.Ensure(context.Background(), f.set)
	if err != nil || out != OutcomeNewlyEnrolled {
		t.Fatalf("ensure %v %v logs %v", out, err, f.logs)
	}
	if !f.sys.ran("dpkg -i ") || !f.sys.ran("systemctl enable inventory-agent") || !f.sys.ran("systemctl restart inventory-agent") {
		t.Fatalf("calls %v", f.sys.calls)
	}
	key, _ := os.ReadFile(f.in.Paths.KeyFile)
	fi, _ := os.Stat(f.in.Paths.KeyFile)
	if strings.TrimSpace(string(key)) != "aks_secret" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file %q %v", key, fi.Mode())
	}
	cfg, _ := os.ReadFile(f.in.Paths.Config)
	if !strings.Contains(string(cfg), "key_id: ak_0123456789abcdef01234567") || !strings.Contains(string(cfg), "ingest_endpoint: portal.example.org:9977") {
		t.Fatalf("config %s", cfg)
	}
	// Second run: already enrolled, nothing is done.
	f.sys.calls = nil
	if out, err := f.in.Ensure(context.Background(), f.set); err != nil || out != OutcomeEnrolled || len(f.sys.calls) != 0 {
		t.Fatalf("second run %v %v %v", out, err, f.sys.calls)
	}
}

// A CA bundle from the platform is written for the agent and referenced.
func TestEnsureWritesCABundle(t *testing.T) {
	f := newEnsureFx(t)
	f.set.CAPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if out, err := f.in.Ensure(context.Background(), f.set); err != nil || out != OutcomeNewlyEnrolled {
		t.Fatalf("%v %v", out, err)
	}
	if b, _ := os.ReadFile(f.in.Paths.CAFile); !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Fatalf("ca %q", b)
	}
	if cfg, _ := os.ReadFile(f.in.Paths.Config); !strings.Contains(string(cfg), "ca_file: "+f.in.Paths.CAFile) {
		t.Fatalf("config %s", cfg)
	}
	f.set.CAFile = "/x"
	if _, err := f.in.Ensure(context.Background(), f.set); err == nil {
		t.Fatal("CA file and bundle together accepted")
	}
}

func TestEnsureUpgradesOldAgentAndRPM(t *testing.T) {
	f := newEnsureFx(t)
	f.sys.pkgTool, f.sys.installed = "rpm", "4.4.0"
	if out, err := f.in.Ensure(context.Background(), f.set); err != nil || out != OutcomeNewlyEnrolled || !f.sys.ran("rpm -U --replacepkgs ") {
		t.Fatalf("rpm upgrade %v %v %v", out, err, f.sys.calls)
	}
}

func TestEnsureCurrentAgentIsNotReinstalled(t *testing.T) {
	f := newEnsureFx(t)
	f.sys.installed = "4.5.1"
	f.set.Key, f.set.KeyFile = "", filepath.Join(f.dir, "client.key")
	_ = os.WriteFile(f.set.KeyFile, []byte("aks_from_file\n"), 0o600)
	if out, err := f.in.Ensure(context.Background(), f.set); err != nil || out != OutcomeNewlyEnrolled || f.sys.ran("dpkg -i") {
		t.Fatalf("%v %v %v", out, err, f.sys.calls)
	}
	if b, _ := os.ReadFile(f.in.Paths.KeyFile); strings.TrimSpace(string(b)) != "aks_from_file" {
		t.Fatalf("key %q", b)
	}
	if f.rel.hits["/repo/releases/latest"] != 0 {
		t.Fatal("GitHub contacted although the agent is current")
	}
}

func TestEnsurePendingAndSkips(t *testing.T) {
	ctx := context.Background()
	f := newEnsureFx(t)
	f.sys.onRestart = nil // the agent does not enroll (e.g. outside the key's networks)
	if out, err := f.in.Ensure(ctx, f.set); err != nil || out != OutcomePending {
		t.Fatalf("pending %v %v", out, err)
	}
	// Nothing changed since: no restart, no waiting.
	f.sys.calls = nil
	if out, err := f.in.Ensure(ctx, f.set); err != nil || out != OutcomePending || f.sys.ran("systemctl") {
		t.Fatalf("unchanged re-check %v %v %v", out, err, f.sys.calls)
	}

	cases := map[Outcome]func(f *fx){
		OutcomeNotConfigured: func(f *fx) { f.set = Settings{} },
		OutcomeNotRoot:       func(f *fx) { f.sys.root = false },
		OutcomeUnsupported:   func(f *fx) { f.sys.pkgTool = "" },
		OutcomeUnmanaged: func(f *fx) {
			_ = os.MkdirAll(filepath.Dir(f.in.Paths.Binary), 0o755)
			_ = os.WriteFile(f.in.Paths.Binary, []byte("bin"), 0o755)
		},
		OutcomeForeign: func(f *fx) {
			f.sys.installed = "4.5.1"
			_ = os.MkdirAll(filepath.Dir(f.in.Paths.Config), 0o755)
			_ = os.WriteFile(f.in.Paths.Config, []byte("ingest_endpoint: elsewhere:9977\n"), 0o644)
		},
	}
	for want, setup := range cases {
		f := newEnsureFx(t)
		setup(f)
		if out, err := f.in.Ensure(ctx, f.set); err != nil || out != want {
			t.Errorf("%s: got %v %v", want, out, err)
		}
	}
	f = newEnsureFx(t)
	f.in.Arch = "386"
	if out, _ := f.in.Ensure(ctx, f.set); out != OutcomeUnsupported {
		t.Errorf("arch: %v", out)
	}
}

func TestEnsureErrors(t *testing.T) {
	ctx := context.Background()
	invalid := []func(s *Settings){
		func(s *Settings) { s.Ingest = "no-port" },
		func(s *Settings) { s.KeyID = "ak_bad" },
		func(s *Settings) { s.KeyFile = "/k" },  // both key and key file
		func(s *Settings) { s.Key = "" },        // neither
		func(s *Settings) { s.Version = "abc" }, // bad version
	}
	for i, mut := range invalid {
		f := newEnsureFx(t)
		mut(&f.set)
		if _, err := f.in.Ensure(ctx, f.set); err == nil {
			t.Errorf("invalid settings %d accepted", i)
		}
	}
	errCases := map[string]func(f *fx){
		"bad keyring":     func(f *fx) { f.set.ReleaseKeys = "x" },
		"tampered pkg":    func(f *fx) { f.rel.bad = true },
		"untrusted key":   func(f *fx) { f.set.ReleaseKeys = DefaultReleaseKeys },
		"old release":     func(f *fx) { f.rel.tag = "v4.4.0" },
		"missing version": func(f *fx) { f.set.Version = "4.9.9" },
		"dpkg fails":      func(f *fx) { f.sys.failCmd = "dpkg -i" },
		"systemctl fails": func(f *fx) { f.sys.failCmd = "systemctl enable" },
		"missing key file": func(f *fx) {
			f.set.Key, f.set.KeyFile = "", filepath.Join(f.dir, "missing.key")
		},
		"empty key file": func(f *fx) {
			f.set.Key, f.set.KeyFile = "", filepath.Join(f.dir, "empty.key")
			_ = os.WriteFile(f.set.KeyFile, []byte("\n"), 0o600)
		},
		"no platform": func(f *fx) { f.in.Arch = "arm64" },
	}
	for name, setup := range errCases {
		f := newEnsureFx(t)
		setup(f)
		if _, err := f.in.Ensure(ctx, f.set); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// Cancelled while waiting for the credential.
	f := newEnsureFx(t)
	f.sys.onRestart = nil
	f.in.Wait = time.Minute
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if out, err := f.in.Ensure(cctx, f.set); out != OutcomePending || err == nil {
		t.Errorf("cancel: %v %v", out, err)
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"4.5.1", "4.5.1", 0}, {"4.4.9", "4.5.1", -1}, {"v4.10.0", "4.9.9", 1}, {"4.5.1-rc1", "4.5.1", 0}} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s = %d", c.a, c.b, got)
		}
	}
	if New(Source{}).Arch == "" || DefaultPaths().KeyFile != "/etc/inventory-agent/auto-enroll.key" {
		t.Error("defaults")
	}
}
