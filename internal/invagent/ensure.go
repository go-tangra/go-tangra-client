// Package invagent makes sure the go-tangra v4 inventory agent is installed
// on the host and enrolled with the platform through automatic enrollment
// (go-tangra-inventory feature 029). It runs after a client update and when
// the daemon starts, and does nothing unless auto-enrollment is configured:
//
//  1. an agent that already holds a credential is left alone;
//  2. otherwise the agent package (deb or rpm, installed or older than the
//     first version that supports automatic enrollment) is taken from the
//     go-tangra-inventory GitHub release, verified against the signed
//     release manifest (ed25519, the agents' own release key) and its size
//     and SHA-256, and installed with dpkg or rpm;
//  3. the key secret is written to /etc/inventory-agent/auto-enroll.key
//     (0600) and agent.yaml gets ingest_endpoint and auto_enroll; an agent
//     configured for another endpoint is never repointed;
//  4. the agent service is (re)started and the client waits for the agent
//     to store its credential.
package invagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// MinAgentVersion is the first agent release with automatic enrollment.
const MinAgentVersion = "4.5.1"

// PackageName is the agent's deb/rpm package name.
const PackageName = "tangra-inventory-agent"

// Outcome of Ensure.
type Outcome string

const (
	OutcomeNotConfigured Outcome = "not_configured"
	OutcomeNotRoot       Outcome = "not_root"
	OutcomeUnsupported   Outcome = "unsupported_platform"
	OutcomeUnmanaged     Outcome = "unmanaged_agent"    // a binary not installed by the package manager
	OutcomeForeign       Outcome = "foreign_config"     // configured for another ingest endpoint
	OutcomeEnrolled      Outcome = "already_enrolled"   // held a credential before
	OutcomeNewlyEnrolled Outcome = "enrolled"           // enrolled during this run
	OutcomePending       Outcome = "enrollment_pending" // started, no credential yet
)

// Settings come from the client configuration.
type Settings struct {
	Ingest      string // host:port of the inventory ingest edge
	KeyID       string // ak_…
	Key         string // aks_… (or KeyFile)
	KeyFile     string // file holding the key secret
	CAFile      string // optional CA bundle of the ingest certificate (on this host)
	CAPEM       string // or the CA bundle itself (written to Paths.CAFile)
	ServerName  string // optional certificate name override
	Version     string // agent release to install: "" / "latest" or 4.x.y
	ReleaseKeys string // keyring override; "" = DefaultReleaseKeys
}

var autoKeyIDRE = regexp.MustCompile(`^ak_[0-9a-f]{24}$`)

// Configured reports whether automatic enrollment is set up at all.
func (s Settings) Configured() bool {
	return s.Ingest != "" || s.KeyID != "" || s.Key != "" || s.KeyFile != ""
}

// Validate checks the settings.
func (s Settings) Validate() error {
	if _, port, err := net.SplitHostPort(s.Ingest); err != nil || port == "" {
		return fmt.Errorf("invagent: inventory-ingest %q must be host:port", s.Ingest)
	}
	if !autoKeyIDRE.MatchString(s.KeyID) {
		return errors.New("invagent: inventory-auto-enroll-key-id must be ak_ followed by 24 hex characters")
	}
	if (s.Key == "") == (s.KeyFile == "") {
		return errors.New("invagent: set exactly one of inventory-auto-enroll-key and inventory-auto-enroll-key-file")
	}
	if s.CAFile != "" && s.CAPEM != "" {
		return errors.New("invagent: set either an inventory CA file or a CA bundle, not both")
	}
	if s.Version != "" && s.Version != "latest" && !versionRE.MatchString(strings.TrimPrefix(s.Version, "v")) {
		return fmt.Errorf("invagent: inventory-agent-version %q is not a release version", s.Version)
	}
	return nil
}

// System runs host commands (exec in production, a fake in tests).
type System interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	LookPath(name string) (string, error)
	Geteuid() int
}

// Exec is the production System.
type Exec struct{}

func (Exec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed commands and verified package paths
}
func (Exec) LookPath(name string) (string, error) { return exec.LookPath(name) }
func (Exec) Geteuid() int                         { return os.Geteuid() }

// Paths of the agent on the host.
type Paths struct {
	Binary     string
	Config     string
	KeyFile    string
	Credential string
	CAFile     string // where a CA bundle handed over by the platform is written
	TempDir    string
}

// DefaultPaths are the packaged agent's paths.
func DefaultPaths() Paths {
	return Paths{Binary: "/usr/bin/inventory-agent", Config: "/etc/inventory-agent/agent.yaml",
		KeyFile: "/etc/inventory-agent/auto-enroll.key", Credential: "/var/lib/inventory-agent/credential",
		CAFile: "/etc/inventory-agent/ingest-ca.pem", TempDir: os.TempDir()}
}

// Installer carries the dependencies of Ensure.
type Installer struct {
	Sys   System
	Src   Source
	Paths Paths
	Arch  string        // runtime.GOARCH by default
	Wait  time.Duration // how long to wait for the credential (default 60s)
	Poll  time.Duration // credential poll interval (default 2s)
	Logf  func(format string, args ...any)
}

// New returns an Installer for this host.
func New(src Source) *Installer {
	return &Installer{Sys: Exec{}, Src: src, Paths: DefaultPaths(), Arch: runtime.GOARCH, Wait: 60 * time.Second, Poll: 2 * time.Second,
		Logf: func(f string, a ...any) { fmt.Printf("Inventory agent: "+f+"\n", a...) }}
}

// Ensure installs and enrolls the agent as described in the package doc.
func (in *Installer) Ensure(ctx context.Context, s Settings) (Outcome, error) {
	if !s.Configured() {
		return OutcomeNotConfigured, nil
	}
	if err := s.Validate(); err != nil {
		return OutcomeNotConfigured, err
	}
	if in.Sys.Geteuid() != 0 {
		in.Logf("skipped: installing the agent needs root")
		return OutcomeNotRoot, nil
	}
	if nonEmpty(in.Paths.Credential) {
		return OutcomeEnrolled, nil
	}
	pkg := in.packageType()
	if pkg == "" || (in.Arch != "amd64" && in.Arch != "arm64") {
		in.Logf("skipped: no dpkg or rpm, or unsupported architecture %s", in.Arch)
		return OutcomeUnsupported, nil
	}
	version := in.installedVersion(ctx, pkg)
	if version == "" && exists(in.Paths.Binary) {
		in.Logf("skipped: %s is not managed by the package manager", in.Paths.Binary)
		return OutcomeUnmanaged, nil
	}
	changed := false
	if version == "" || compareVersions(version, MinAgentVersion) < 0 {
		if err := in.install(ctx, s, pkg, version); err != nil {
			return "", err
		}
		changed = true
	}
	keyChanged, err := in.writeKey(s)
	if err != nil {
		return "", err
	}
	changed = changed || keyChanged
	caFile := s.CAFile
	if s.CAPEM != "" {
		want := []byte(strings.TrimSpace(s.CAPEM) + "\n")
		if cur, err := os.ReadFile(in.Paths.CAFile); err != nil || string(cur) != string(want) {
			if err := writeAtomic(in.Paths.CAFile, want, 0o644); err != nil {
				return "", err
			}
			changed = true
		}
		caFile = in.Paths.CAFile
	}
	cfgChanged, err := Configure(in.Paths.Config, AgentSettings{Ingest: s.Ingest, KeyID: s.KeyID, KeyFile: in.Paths.KeyFile, CAFile: caFile, ServerName: s.ServerName})
	if err != nil {
		if errors.Is(err, ErrForeignConfig) {
			in.Logf("skipped: %v", err)
			return OutcomeForeign, nil
		}
		return "", err
	}
	if !changed && !cfgChanged {
		// Nothing new to apply: the agent keeps retrying by itself.
		return OutcomePending, nil
	}
	for _, args := range [][]string{{"enable", "inventory-agent"}, {"restart", "inventory-agent"}} {
		if out, err := in.Sys.Run(ctx, "systemctl", args...); err != nil {
			return "", fmt.Errorf("invagent: systemctl %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))
		}
	}
	in.Logf("started; waiting for automatic enrollment with key %s", s.KeyID)
	deadline := time.Now().Add(in.Wait)
	for {
		if nonEmpty(in.Paths.Credential) {
			in.Logf("enrolled")
			return OutcomeNewlyEnrolled, nil
		}
		if !time.Now().Before(deadline) {
			in.Logf("not enrolled yet; see journalctl -u inventory-agent (the key's networks, the switch in Inventory > Agents > Automatic enrollment)")
			return OutcomePending, nil
		}
		select {
		case <-ctx.Done():
			return OutcomePending, ctx.Err()
		case <-time.After(in.Poll):
		}
	}
}

func (in *Installer) packageType() string {
	if _, err := in.Sys.LookPath("dpkg"); err == nil {
		return "deb"
	}
	if _, err := in.Sys.LookPath("rpm"); err == nil {
		return "rpm"
	}
	return ""
}

// installedVersion is the package's version ("" when not installed).
func (in *Installer) installedVersion(ctx context.Context, pkg string) string {
	var out []byte
	var err error
	if pkg == "deb" {
		out, err = in.Sys.Run(ctx, "dpkg-query", "-W", "-f=${Status}|${Version}", PackageName)
		if err != nil || !strings.HasPrefix(string(out), "install ok installed|") {
			return ""
		}
		out = []byte(strings.TrimPrefix(string(out), "install ok installed|"))
	} else {
		out, err = in.Sys.Run(ctx, "rpm", "-q", "--qf", "%{VERSION}", PackageName)
		if err != nil {
			return ""
		}
	}
	v := strings.TrimSpace(string(out))
	if i := strings.IndexAny(v, "-~+"); i > 0 { // deb/rpm revision suffixes
		v = v[:i]
	}
	if !versionRE.MatchString(v) {
		return ""
	}
	return v
}

func (in *Installer) install(ctx context.Context, s Settings, pkg, current string) error {
	keys, err := ParseKeyring(orDefault(s.ReleaseKeys, DefaultReleaseKeys))
	if err != nil {
		return err
	}
	rel, err := in.Src.Release(ctx, s.Version)
	if err != nil {
		return err
	}
	m, err := in.Src.Manifest(ctx, rel, keys)
	if err != nil {
		return err
	}
	if compareVersions(m.Version, MinAgentVersion) < 0 {
		return fmt.Errorf("invagent: release %s predates automatic enrollment (%s)", m.Version, MinAgentVersion)
	}
	a, err := m.Select("linux", in.Arch, pkg)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(in.Paths.TempDir, "tangra-inventory-agent-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, a.File)
	if current == "" {
		in.Logf("installing %s %s (signed release, verified)", PackageName, m.Version)
	} else {
		in.Logf("upgrading %s %s -> %s (signed release, verified)", PackageName, current, m.Version)
	}
	if err := in.Src.Download(ctx, rel, a, file); err != nil {
		return err
	}
	cmd, args := "dpkg", []string{"-i", file}
	if pkg == "rpm" {
		cmd, args = "rpm", []string{"-U", "--replacepkgs", file}
	}
	if out, err := in.Sys.Run(ctx, cmd, args...); err != nil {
		return fmt.Errorf("invagent: %s: %v: %s", cmd, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// writeKey stores the key secret for the agent (0600, root only) and
// reports whether the file changed.
func (in *Installer) writeKey(s Settings) (bool, error) {
	key := s.Key
	if s.KeyFile != "" {
		if filepath.Clean(s.KeyFile) == filepath.Clean(in.Paths.KeyFile) {
			return false, nil
		}
		b, err := os.ReadFile(s.KeyFile) // #nosec G304 -- operator-configured key file
		if err != nil {
			return false, fmt.Errorf("invagent: read inventory-auto-enroll-key-file: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if key == "" {
		return false, errors.New("invagent: the auto-enrollment key is empty")
	}
	if cur, err := os.ReadFile(in.Paths.KeyFile); err == nil && strings.TrimSpace(string(cur)) == key {
		return false, nil
	}
	return true, writeAtomic(in.Paths.KeyFile, []byte(key+"\n"), 0o600)
}

func nonEmpty(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// compareVersions compares x.y.z release versions (pre-release suffixes are
// ignored).
func compareVersions(a, b string) int {
	pa, pb := parts(a), parts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parts(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
