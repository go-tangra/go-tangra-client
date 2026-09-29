package invagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// DefaultReleaseKeys is the inventory agent release signing keyring
// (go-tangra-inventory repository variable AGENT_RELEASE_PUBLIC_KEYS); the
// same key the agents themselves trust for self-upgrades.
const DefaultReleaseKeys = "release-2026:Hrddhwn4fQBlaYhfZJtpNkFvAojDB4VXbq4V5CBX+pw="

// Release file names on the go-tangra-inventory GitHub release.
const (
	manifestFile  = "agent-release.json"
	signatureFile = "agent-release.json.sig"
)

// Bounds (the inventory manifest contract).
const (
	maxManifestBytes = 64 << 10
	maxArtifactBytes = 150 << 20
)

// Verification errors.
var (
	ErrUnknownKey = errors.New("invagent: release signed with an unknown key")
	ErrSignature  = errors.New("invagent: release signature invalid")
	ErrManifest   = errors.New("invagent: invalid release manifest")
	ErrPlatform   = errors.New("invagent: no agent package for this platform")
	ErrArtifact   = errors.New("invagent: package does not match the signed manifest")
)

var (
	versionRE      = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)
	fileRE         = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,128}$`)
	sha256RE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	releaseKeyIDRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// Keyring maps key ids to ed25519 public keys.
type Keyring map[string]ed25519.PublicKey

// ParseKeyring parses "<id>:<base64 key>[,<id>:<key>]".
func ParseKeyring(s string) (Keyring, error) {
	k := Keyring{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, b64, ok := strings.Cut(part, ":")
		if !ok || !releaseKeyIDRE.MatchString(id) {
			return nil, fmt.Errorf("invagent: keyring entry %q: want <id>:<base64 key>", part)
		}
		pub, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invagent: keyring entry %q: not an ed25519 public key", id)
		}
		k[id] = ed25519.PublicKey(pub)
	}
	if len(k) == 0 {
		return nil, errors.New("invagent: empty keyring")
	}
	return k, nil
}

// Artifact is one platform package of a release.
type Artifact struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	InstallType string `json:"install_type"`
	File        string `json:"file"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

// Manifest is the signed description of an agent release.
type Manifest struct {
	Schema    int        `json:"schema"`
	Version   string     `json:"version"`
	CreatedAt string     `json:"created_at"`
	KeyID     string     `json:"key_id"`
	Artifacts []Artifact `json:"artifacts"`
}

// Verify checks the ed25519 signature of the raw manifest bytes with the
// key the manifest names, then parses the manifest strictly.
func (k Keyring) Verify(manifest, sigFile []byte) (Manifest, error) {
	if len(manifest) > maxManifestBytes {
		return Manifest{}, ErrManifest
	}
	var head struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(manifest, &head); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	pub, ok := k[head.KeyID]
	if !ok {
		return Manifest{}, fmt.Errorf("%w: %q", ErrUnknownKey, head.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigFile)))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, manifest, sig) {
		return Manifest{}, ErrSignature
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	if m.Schema != 1 || !versionRE.MatchString(m.Version) || len(m.Artifacts) == 0 || len(m.Artifacts) > 16 {
		return Manifest{}, ErrManifest
	}
	for _, a := range m.Artifacts {
		if !fileRE.MatchString(a.File) || a.Size < 1 || a.Size > maxArtifactBytes || !sha256RE.MatchString(a.SHA256) {
			return Manifest{}, fmt.Errorf("%w: artifact %q", ErrManifest, a.File)
		}
	}
	return m, nil
}

// Select returns the artifact for the platform.
func (m Manifest) Select(goos, arch, installType string) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.OS == goos && a.Arch == arch && a.InstallType == installType {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: %s/%s %s", ErrPlatform, goos, arch, installType)
}

// Doer performs HTTP requests (http.Client).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Release is a GitHub release of go-tangra-inventory.
type Release struct {
	Tag    string
	Assets map[string]string // name -> download URL
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Source fetches releases from the GitHub API.
type Source struct {
	HTTP Doer
	API  string // e.g. https://api.github.com/repos/go-tangra/go-tangra-inventory
}

func (s Source) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json, application/octet-stream")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invagent: GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("invagent: GET %s: response larger than %d bytes", url, limit)
	}
	return b, nil
}

// Release returns the release for version ("" or "latest": the latest).
func (s Source) Release(ctx context.Context, version string) (Release, error) {
	url := s.API + "/releases/latest"
	if version != "" && version != "latest" {
		url = s.API + "/releases/tags/v" + strings.TrimPrefix(version, "v")
	}
	b, err := s.get(ctx, url, 1<<20)
	if err != nil {
		return Release{}, err
	}
	var r ghRelease
	if err := json.Unmarshal(b, &r); err != nil {
		return Release{}, fmt.Errorf("invagent: release JSON: %w", err)
	}
	out := Release{Tag: r.TagName, Assets: map[string]string{}}
	for _, a := range r.Assets {
		out.Assets[a.Name] = a.URL
	}
	return out, nil
}

// Manifest downloads and verifies the release's signed manifest.
func (s Source) Manifest(ctx context.Context, rel Release, keys Keyring) (Manifest, error) {
	mu, su := rel.Assets[manifestFile], rel.Assets[signatureFile]
	if mu == "" || su == "" {
		return Manifest{}, fmt.Errorf("invagent: release %s carries no signed agent manifest", rel.Tag)
	}
	manifest, err := s.get(ctx, mu, maxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := s.get(ctx, su, 1024)
	if err != nil {
		return Manifest{}, err
	}
	m, err := keys.Verify(manifest, sig)
	if err != nil {
		return Manifest{}, err
	}
	if tag := strings.TrimPrefix(rel.Tag, "v"); tag != m.Version {
		return Manifest{}, fmt.Errorf("%w: manifest version %s in release %s", ErrManifest, m.Version, rel.Tag)
	}
	return m, nil
}

// Download writes the artifact to path (0600) and checks size and sha256
// against the signed manifest entry; a mismatching file is removed.
func (s Source) Download(ctx context.Context, rel Release, a Artifact, path string) (err error) {
	url := rel.Assets[a.File]
	if url == "" {
		return fmt.Errorf("invagent: release %s has no asset %s", rel.Tag, a.File)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invagent: GET %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- path chosen by the caller in its temp dir
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, a.Size+1))
	if err != nil {
		return err
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("%w: %s", ErrArtifact, a.File)
	}
	return nil
}
