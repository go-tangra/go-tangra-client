package updater

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/minio/selfupdate"
)

const (
	githubAPIURL = "https://api.github.com/repos/go-tangra/go-tangra-client/releases/latest"
	binaryPrefix = "tangra-client"
)

// UpdateResult holds the result of a version check.
type UpdateResult struct {
	CurrentVersion string
	LatestVersion  string
	UpdateAvail    bool
	BinaryURL      string
	ChecksumURL    string
	BinaryName     string
	ReleaseURL     string
	ExpectedSHA256 string // hex-encoded; set by the executor source
}

// Environment describes the runtime environment.
type Environment struct {
	IsDocker    bool
	IsK8s       bool
	IsSystemd   bool
	IsPackaged  bool
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	HTMLURL string        `json:"html_url"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// transientStatus reports whether an HTTP status warrants a retry. GitHub
// occasionally returns 5xx gateway errors (e.g. 502/503/504) or 429 rate limits
// that succeed on a second attempt.
func transientStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// getWithRetry performs a GET with a few backoff retries on network errors and
// transient HTTP statuses, so a single flaky GitHub response doesn't abort an
// update. The returned response (on success) has an open Body the caller closes.
func getWithRetry(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	const maxAttempts = 4
	backoff := time.Second
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
		} else if transientStatus(resp.StatusCode) {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			return resp, nil // success, or a non-retryable status the caller handles
		}

		if attempt == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, fmt.Errorf("after %d attempts: %w", maxAttempts, lastErr)
}

// CheckForUpdate queries GitHub for the latest release and compares versions.
func CheckForUpdate(ctx context.Context, currentVersion string) (*UpdateResult, error) {
	resp, err := getWithRetry(ctx, githubAPIURL, map[string]string{"Accept": "application/vnd.github+json"})
	if err != nil {
		return nil, fmt.Errorf("fetching latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	binaryName := fmt.Sprintf("%s-%s-%s", binaryPrefix, runtime.GOOS, runtime.GOARCH)
	checksumName := fmt.Sprintf("%s-checksums.sha256", binaryPrefix)

	result := &UpdateResult{
		CurrentVersion: currentVersion,
		LatestVersion:  latestVersion,
		UpdateAvail:    compareVersions(currentVersion, latestVersion) < 0,
		BinaryName:     binaryName,
		ReleaseURL:     release.HTMLURL,
	}

	for _, asset := range release.Assets {
		switch asset.Name {
		case binaryName:
			result.BinaryURL = asset.BrowserDownloadURL
		case checksumName:
			result.ChecksumURL = asset.BrowserDownloadURL
		}
	}

	if result.UpdateAvail && result.BinaryURL == "" {
		return nil, fmt.Errorf("no binary found for %s/%s in release %s", runtime.GOOS, runtime.GOARCH, release.TagName)
	}

	return result, nil
}

// DownloadAndApply downloads the binary and applies it with checksum verification.
func DownloadAndApply(ctx context.Context, result *UpdateResult) error {
	// Download checksum file
	var expectedChecksum []byte
	if result.ChecksumURL != "" {
		checksum, err := downloadChecksum(ctx, result.ChecksumURL, result.BinaryName)
		if err != nil {
			return fmt.Errorf("downloading checksums: %w", err)
		}
		expectedChecksum = checksum
	}

	// Download binary
	fmt.Printf("Downloading %s...\n", result.BinaryName)
	resp, err := getWithRetry(ctx, result.BinaryURL, nil)
	if err != nil {
		return fmt.Errorf("downloading binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	contentLength := resp.ContentLength
	reader := io.Reader(resp.Body)

	// Wrap with progress reporting if content length is known
	if contentLength > 0 {
		reader = &progressReader{
			reader: resp.Body,
			total:  contentLength,
		}
	}

	return applyBinary(reader, expectedChecksum, result.LatestVersion)
}

// applyBinary applies an update from reader, verifying the SHA-256 checksum
// when expectedChecksum is non-nil. Shared by the GitHub and executor sources.
func applyBinary(reader io.Reader, expectedChecksum []byte, version string) error {
	opts := selfupdate.Options{}
	if expectedChecksum != nil {
		opts.Hash = crypto.SHA256
		opts.Checksum = expectedChecksum
	}

	if err := selfupdate.Apply(reader, opts); err != nil {
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			return fmt.Errorf("update failed and rollback also failed: %w", rerr)
		}
		return fmt.Errorf("update failed (rolled back): %w", err)
	}

	fmt.Printf("\nSuccessfully updated to v%s\n", version)
	return nil
}

func downloadChecksum(ctx context.Context, checksumURL, targetFilename string) ([]byte, error) {
	resp, err := getWithRetry(ctx, checksumURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksum download returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseChecksumFile(string(body), targetFilename)
}

// parseChecksumFile parses a sha256sum-format file and returns the checksum for the target filename.
func parseChecksumFile(content, targetFilename string) ([]byte, error) {
	for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		// sha256sum format: "<hash>  <filename>" or "<hash> <filename>"
		filename := strings.TrimPrefix(parts[1], "*")
		if filename == targetFilename {
			return hex.DecodeString(parts[0])
		}
	}
	return nil, fmt.Errorf("checksum not found for %s", targetFilename)
}

// compareVersions compares two semver strings. Returns -1, 0, or 1.
// Strips "v" prefix and any pre-release suffix (e.g., "-rc1").
func compareVersions(current, latest string) int {
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	// Strip pre-release suffix
	if idx := strings.IndexByte(current, '-'); idx != -1 {
		current = current[:idx]
	}
	if idx := strings.IndexByte(latest, '-'); idx != -1 {
		latest = latest[:idx]
	}

	cParts := strings.Split(current, ".")
	lParts := strings.Split(latest, ".")

	maxLen := len(cParts)
	if len(lParts) > maxLen {
		maxLen = len(lParts)
	}

	for i := 0; i < maxLen; i++ {
		var c, l int
		if i < len(cParts) {
			c, _ = strconv.Atoi(cParts[i])
		}
		if i < len(lParts) {
			l, _ = strconv.Atoi(lParts[i])
		}
		if c < l {
			return -1
		}
		if c > l {
			return 1
		}
	}
	return 0
}

// DetectEnvironment checks the runtime environment.
func DetectEnvironment() Environment {
	env := Environment{}

	// Docker: check for /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		env.IsDocker = true
	}

	// Kubernetes: check for KUBERNETES_SERVICE_HOST
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		env.IsK8s = true
	}

	// Systemd: check for INVOCATION_ID
	if os.Getenv("INVOCATION_ID") != "" {
		env.IsSystemd = true
	}

	// Package-managed: check if binary is in /usr/local/bin or /usr/bin
	exe, err := os.Executable()
	if err == nil {
		if strings.HasPrefix(exe, "/usr/local/bin/") || strings.HasPrefix(exe, "/usr/bin/") {
			env.IsPackaged = true
		}
	}

	return env
}

// progressReader wraps a reader and prints download progress.
type progressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	lastPct    int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)

	pct := int(pr.read * 100 / pr.total)
	// Print at every 10% increment
	if pct/10 > pr.lastPct/10 {
		pr.lastPct = pct
		fmt.Printf("  %d%%\n", pct)
	}

	return n, err
}
