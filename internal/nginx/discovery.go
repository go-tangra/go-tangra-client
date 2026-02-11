package nginx

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// CommonNginxPaths contains common nginx installation paths
var CommonNginxPaths = []string{
	"/etc/nginx",
	"/usr/local/nginx/conf",
	"/usr/local/etc/nginx",
	"/opt/nginx/conf",
	"/opt/homebrew/etc/nginx",
}

// CommonNginxBinaries contains common nginx binary locations
var CommonNginxBinaries = []string{
	"nginx",
	"/usr/sbin/nginx",
	"/usr/local/sbin/nginx",
	"/usr/local/nginx/sbin/nginx",
	"/opt/nginx/sbin/nginx",
	"/opt/homebrew/bin/nginx",
}

// NginxInfo contains discovered nginx installation information
type NginxInfo struct {
	BinaryPath    string
	Version       string
	ConfigPath    string // Main nginx.conf path
	ConfigDir     string // Directory containing nginx.conf
	PrefixPath    string // --prefix value
	SitesEnabled  string // sites-enabled directory (if exists)
	SitesAvail    string // sites-available directory (if exists)
	ConfD         string // conf.d directory (if exists)
	ErrorLogPath  string
	AccessLogPath string
	PIDPath       string
	IsRunning     bool
}

// Discover attempts to find nginx installation and configuration
func Discover() (*NginxInfo, error) {
	info := &NginxInfo{}

	// Find nginx binary
	binary, err := findNginxBinary()
	if err != nil {
		return nil, fmt.Errorf("nginx not found: %w", err)
	}
	info.BinaryPath = binary

	// Get nginx version and compile-time configuration
	if err := info.parseNginxV(); err != nil {
		return nil, fmt.Errorf("failed to get nginx info: %w", err)
	}

	// Find additional directories
	info.findAdditionalDirs()

	// Check if nginx is running
	info.IsRunning = isNginxRunning(info.PIDPath)

	return info, nil
}

// findNginxBinary locates the nginx binary
func findNginxBinary() (string, error) {
	// First try PATH
	if path, err := exec.LookPath("nginx"); err == nil {
		return path, nil
	}

	// Try common locations
	for _, path := range CommonNginxBinaries {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("nginx binary not found in PATH or common locations")
}

// parseNginxV parses the output of `nginx -V`
func (info *NginxInfo) parseNginxV() error {
	cmd := exec.Command(info.BinaryPath, "-V")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// nginx -V returns output on stderr and exit code 0
		if stderr.Len() == 0 {
			return fmt.Errorf("failed to run nginx -V: %w", err)
		}
	}

	output := stderr.String()

	// Parse version
	versionRe := regexp.MustCompile(`nginx version: nginx/(\S+)`)
	if matches := versionRe.FindStringSubmatch(output); len(matches) > 1 {
		info.Version = matches[1]
	}

	// Parse configure arguments
	configRe := regexp.MustCompile(`configure arguments: (.+)`)
	if matches := configRe.FindStringSubmatch(output); len(matches) > 1 {
		args := matches[1]

		// Parse individual arguments
		info.PrefixPath = extractArg(args, "--prefix=")
		info.ConfigPath = extractArg(args, "--conf-path=")
		info.ErrorLogPath = extractArg(args, "--error-log-path=")
		info.AccessLogPath = extractArg(args, "--http-log-path=")
		info.PIDPath = extractArg(args, "--pid-path=")
	}

	// Fallback: find config path
	if info.ConfigPath == "" {
		info.ConfigPath = info.findConfigPath()
	}

	if info.ConfigPath != "" {
		info.ConfigDir = filepath.Dir(info.ConfigPath)
	}

	return nil
}

// extractArg extracts a value from nginx configure arguments
func extractArg(args, prefix string) string {
	start := strings.Index(args, prefix)
	if start == -1 {
		return ""
	}
	start += len(prefix)

	// Find the end (next space or end of string)
	end := start
	for end < len(args) && args[end] != ' ' {
		end++
	}

	return args[start:end]
}

// findConfigPath tries to locate nginx.conf
func (info *NginxInfo) findConfigPath() string {
	// Try common paths
	for _, dir := range CommonNginxPaths {
		configPath := filepath.Join(dir, "nginx.conf")
		if _, err := os.Stat(configPath); err == nil {
			return configPath
		}
	}

	// Try using nginx -t to find config
	cmd := exec.Command(info.BinaryPath, "-t")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Run()

	// Parse output for config file path
	output := stderr.String()
	re := regexp.MustCompile(`nginx: the configuration file (\S+) syntax is ok`)
	if matches := re.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// findAdditionalDirs locates sites-enabled, sites-available, and conf.d
func (info *NginxInfo) findAdditionalDirs() {
	if info.ConfigDir == "" {
		return
	}

	// Check for sites-enabled
	sitesEnabled := filepath.Join(info.ConfigDir, "sites-enabled")
	if isDir(sitesEnabled) {
		info.SitesEnabled = sitesEnabled
	}

	// Check for sites-available
	sitesAvail := filepath.Join(info.ConfigDir, "sites-available")
	if isDir(sitesAvail) {
		info.SitesAvail = sitesAvail
	}

	// Check for conf.d
	confD := filepath.Join(info.ConfigDir, "conf.d")
	if isDir(confD) {
		info.ConfD = confD
	}
}

// isDir checks if a path is a directory
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// isNginxRunning checks if nginx is running by checking PID file
func isNginxRunning(pidPath string) bool {
	if pidPath == "" {
		// Try common PID paths
		pidPaths := []string{
			"/run/nginx.pid",
			"/var/run/nginx.pid",
			"/usr/local/nginx/logs/nginx.pid",
		}
		for _, p := range pidPaths {
			if _, err := os.Stat(p); err == nil {
				pidPath = p
				break
			}
		}
	}

	if pidPath == "" {
		return false
	}

	data, err := os.ReadFile(pidPath)
	if err != nil {
		return false
	}

	pid := strings.TrimSpace(string(data))
	if pid == "" {
		return false
	}

	// Check if process exists
	procPath := filepath.Join("/proc", pid)
	_, err = os.Stat(procPath)
	return err == nil
}

// TestConfig runs nginx -t to test configuration
func (info *NginxInfo) TestConfig() error {
	cmd := exec.Command(info.BinaryPath, "-t")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nginx configuration test failed: %s", stderr.String())
	}

	return nil
}

// Reload sends a reload signal to nginx
func (info *NginxInfo) Reload() error {
	cmd := exec.Command(info.BinaryPath, "-s", "reload")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload nginx: %s", stderr.String())
	}

	return nil
}

// GetIncludedFiles parses nginx.conf and returns all included configuration files
func (info *NginxInfo) GetIncludedFiles() ([]string, error) {
	if info.ConfigPath == "" {
		return nil, fmt.Errorf("nginx config path not found")
	}

	var files []string
	visited := make(map[string]bool)

	if err := info.collectIncludes(info.ConfigPath, &files, visited); err != nil {
		return nil, err
	}

	return files, nil
}

// collectIncludes recursively collects included files
func (info *NginxInfo) collectIncludes(configPath string, files *[]string, visited map[string]bool) error {
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}

	if visited[absPath] {
		return nil
	}
	visited[absPath] = true
	*files = append(*files, absPath)

	file, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	includeRe := regexp.MustCompile(`^\s*include\s+([^;]+);`)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := includeRe.FindStringSubmatch(line); len(matches) > 1 {
			includePath := strings.TrimSpace(matches[1])

			// Handle relative paths
			if !filepath.IsAbs(includePath) {
				includePath = filepath.Join(filepath.Dir(absPath), includePath)
			}

			// Handle glob patterns
			matchedFiles, err := filepath.Glob(includePath)
			if err != nil {
				continue
			}

			for _, f := range matchedFiles {
				if err := info.collectIncludes(f, files, visited); err != nil {
					// Log but continue with other files
					continue
				}
			}
		}
	}

	return scanner.Err()
}

// String returns a human-readable summary of nginx info
func (info *NginxInfo) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Nginx Version: %s\n", info.Version))
	sb.WriteString(fmt.Sprintf("Binary: %s\n", info.BinaryPath))
	sb.WriteString(fmt.Sprintf("Config: %s\n", info.ConfigPath))
	sb.WriteString(fmt.Sprintf("Config Dir: %s\n", info.ConfigDir))
	if info.SitesEnabled != "" {
		sb.WriteString(fmt.Sprintf("Sites Enabled: %s\n", info.SitesEnabled))
	}
	if info.SitesAvail != "" {
		sb.WriteString(fmt.Sprintf("Sites Available: %s\n", info.SitesAvail))
	}
	if info.ConfD != "" {
		sb.WriteString(fmt.Sprintf("Conf.d: %s\n", info.ConfD))
	}
	sb.WriteString(fmt.Sprintf("Running: %v\n", info.IsRunning))
	return sb.String()
}
