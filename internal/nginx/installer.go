package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-client/internal/storage"
)

// InstallOptions contains options for certificate installation
type InstallOptions struct {
	CertName     string   // Name of the certificate in LCM storage
	Domains      []string // Domains to configure (if empty, uses cert's DNS names)
	HTTPSOnly    bool     // Remove HTTP listeners after install
	HTTP2        bool     // Enable HTTP/2
	HSTS         bool     // Enable HSTS header
	HSTSMaxAge   int      // HSTS max-age in seconds (default: 31536000 = 1 year)
	OCSPStapling bool     // Enable OCSP stapling
	SSLProtocols string   // SSL protocols (default: TLSv1.2 TLSv1.3)
	SSLCiphers   string   // SSL ciphers (leave empty for nginx default)
	DHParamPath  string   // Path to DH parameters file
	CreateBackup bool     // Create backup before modifying config
	DryRun       bool     // Show what would be done without making changes
	ReloadNginx  bool     // Reload nginx after installation
}

// DefaultInstallOptions returns sensible default options
func DefaultInstallOptions() *InstallOptions {
	return &InstallOptions{
		HTTP2:        true,
		HSTS:         true,
		HSTSMaxAge:   31536000, // 1 year
		OCSPStapling: true,
		SSLProtocols: "TLSv1.2 TLSv1.3",
		CreateBackup: true,
		ReloadNginx:  true,
	}
}

// InstallResult contains the result of certificate installation
type InstallResult struct {
	Success       bool
	ModifiedFiles []string
	BackupFiles   []string
	Domains       []string
	Errors        []string
	Warnings      []string
}

// Installer handles nginx SSL configuration
type Installer struct {
	nginxInfo *NginxInfo
	certStore *storage.CertStore
	options   *InstallOptions
}

// NewInstaller creates a new nginx SSL installer
func NewInstaller(nginxInfo *NginxInfo, certStore *storage.CertStore, options *InstallOptions) *Installer {
	if options == nil {
		options = DefaultInstallOptions()
	}
	return &Installer{
		nginxInfo: nginxInfo,
		certStore: certStore,
		options:   options,
	}
}

// Install installs certificates and configures SSL for the specified domains
func (i *Installer) Install() (*InstallResult, error) {
	result := &InstallResult{
		Success: true,
	}

	// Verify certificate exists
	if !i.certStore.CertificateExists(i.options.CertName) {
		return nil, fmt.Errorf("certificate '%s' not found in storage", i.options.CertName)
	}

	// Load certificate metadata for domain info
	metadata, err := i.certStore.LoadMetadata(i.options.CertName)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate metadata: %w", err)
	}

	// Determine domains to configure
	domains := i.options.Domains
	if len(domains) == 0 && metadata != nil {
		domains = append(domains, metadata.DNSNames...)
		if metadata.CommonName != "" && !contains(domains, metadata.CommonName) {
			domains = append([]string{metadata.CommonName}, domains...)
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains specified and certificate has no DNS names")
	}
	result.Domains = domains

	// Parse nginx configuration
	parsedConfig, err := ParseConfig(i.nginxInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nginx config: %w", err)
	}

	// Get certificate paths
	certPaths := i.certStore.GetPaths(i.options.CertName)

	// Find server blocks to modify
	for _, domain := range domains {
		block := parsedConfig.FindServerBlockByDomain(domain)
		if block == nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("No server block found for domain '%s'", domain))
			continue
		}

		// Check if already configured with SSL
		if block.SSLEnabled && block.SSLCertPath == certPaths.FullChainFile {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Domain '%s' already configured with this certificate", domain))
			continue
		}

		// Modify the server block
		if err := i.configureServerBlock(block, certPaths, result); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Failed to configure '%s': %v", domain, err))
			result.Success = false
		}
	}

	// Test nginx configuration
	if !i.options.DryRun && len(result.ModifiedFiles) > 0 {
		if err := i.nginxInfo.TestConfig(); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("Nginx configuration test failed: %v", err))
			result.Success = false

			// Restore from backup if test fails
			if i.options.CreateBackup {
				for j, modFile := range result.ModifiedFiles {
					if j < len(result.BackupFiles) {
						i.restoreBackup(modFile, result.BackupFiles[j])
					}
				}
				result.Warnings = append(result.Warnings,
					"Configuration restored from backup due to test failure")
			}
			return result, nil
		}

		// Reload nginx if requested
		if i.options.ReloadNginx && result.Success {
			if err := i.nginxInfo.Reload(); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("Failed to reload nginx: %v", err))
			}
		}
	}

	return result, nil
}

// configureServerBlock modifies a server block to enable SSL
func (i *Installer) configureServerBlock(block *ServerBlock, certPaths *storage.CertPaths, result *InstallResult) error {
	// Read the original file
	content, err := os.ReadFile(block.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Create backup if requested
	if i.options.CreateBackup && !i.options.DryRun {
		backupPath, err := i.createBackup(block.FilePath)
		if err != nil {
			return fmt.Errorf("failed to create backup: %w", err)
		}
		result.BackupFiles = append(result.BackupFiles, backupPath)
	}

	// Generate SSL configuration
	sslConfig := i.generateSSLConfig(certPaths)

	// Modify the server block
	lines := strings.Split(string(content), "\n")
	modified := i.modifyServerBlock(lines, block, sslConfig)

	if i.options.DryRun {
		fmt.Printf("=== Dry Run: Would modify %s ===\n", block.FilePath)
		fmt.Println(strings.Join(modified, "\n"))
		fmt.Println("=== End Dry Run ===")
		return nil
	}

	// Write the modified file
	if err := os.WriteFile(block.FilePath, []byte(strings.Join(modified, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	result.ModifiedFiles = append(result.ModifiedFiles, block.FilePath)
	return nil
}

// generateSSLConfig generates SSL configuration directives
func (i *Installer) generateSSLConfig(certPaths *storage.CertPaths) string {
	var sb strings.Builder

	// SSL certificate paths
	sb.WriteString(fmt.Sprintf("    ssl_certificate %s;\n", certPaths.FullChainFile))
	sb.WriteString(fmt.Sprintf("    ssl_certificate_key %s;\n", certPaths.PrivKeyFile))

	// SSL protocols
	if i.options.SSLProtocols != "" {
		sb.WriteString(fmt.Sprintf("    ssl_protocols %s;\n", i.options.SSLProtocols))
	}

	// SSL ciphers
	if i.options.SSLCiphers != "" {
		sb.WriteString(fmt.Sprintf("    ssl_ciphers %s;\n", i.options.SSLCiphers))
		sb.WriteString("    ssl_prefer_server_ciphers on;\n")
	}

	// DH parameters
	if i.options.DHParamPath != "" {
		sb.WriteString(fmt.Sprintf("    ssl_dhparam %s;\n", i.options.DHParamPath))
	}

	// Session settings
	sb.WriteString("    ssl_session_timeout 1d;\n")
	sb.WriteString("    ssl_session_cache shared:SSL:50m;\n")
	sb.WriteString("    ssl_session_tickets off;\n")

	// OCSP stapling
	if i.options.OCSPStapling {
		sb.WriteString("    ssl_stapling on;\n")
		sb.WriteString("    ssl_stapling_verify on;\n")
		if certPaths.ChainFile != "" {
			sb.WriteString(fmt.Sprintf("    ssl_trusted_certificate %s;\n", certPaths.ChainFile))
		}
	}

	// HSTS
	if i.options.HSTS {
		sb.WriteString(fmt.Sprintf("    add_header Strict-Transport-Security \"max-age=%d; includeSubDomains\" always;\n",
			i.options.HSTSMaxAge))
	}

	return sb.String()
}

// modifyServerBlock modifies the server block in the config lines
func (i *Installer) modifyServerBlock(lines []string, block *ServerBlock, sslConfig string) []string {
	result := make([]string, 0, len(lines)+20)

	// Regex patterns for SSL directives we'll replace
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+`)
	sslKeyRe := regexp.MustCompile(`^\s*ssl_certificate_key\s+`)
	sslProtocolsRe := regexp.MustCompile(`^\s*ssl_protocols\s+`)
	sslCiphersRe := regexp.MustCompile(`^\s*ssl_ciphers\s+`)
	sslSessionRe := regexp.MustCompile(`^\s*ssl_session_`)
	sslStaplingRe := regexp.MustCompile(`^\s*ssl_stapling`)
	sslDHParamRe := regexp.MustCompile(`^\s*ssl_dhparam\s+`)
	sslTrustedRe := regexp.MustCompile(`^\s*ssl_trusted_certificate\s+`)
	sslPreferRe := regexp.MustCompile(`^\s*ssl_prefer_server_ciphers\s+`)
	hstsRe := regexp.MustCompile(`^\s*add_header\s+Strict-Transport-Security\s+`)
	listenRe := regexp.MustCompile(`^\s*listen\s+`)

	inBlock := false
	sslConfigInserted := false
	blockBraces := 0

	for lineNum, line := range lines {
		// Check if we're entering the target block
		if lineNum+1 >= block.LineStart && lineNum+1 <= block.LineEnd {
			if !inBlock && strings.Contains(line, "server") && strings.Contains(line, "{") {
				inBlock = true
				blockBraces = strings.Count(line, "{") - strings.Count(line, "}")
			} else if inBlock {
				blockBraces += strings.Count(line, "{") - strings.Count(line, "}")
			}
		}

		if inBlock && lineNum+1 >= block.LineStart && lineNum+1 <= block.LineEnd {
			// Skip existing SSL directives that we'll replace
			if sslCertRe.MatchString(line) || sslKeyRe.MatchString(line) ||
				sslProtocolsRe.MatchString(line) || sslCiphersRe.MatchString(line) ||
				sslSessionRe.MatchString(line) || sslStaplingRe.MatchString(line) ||
				sslDHParamRe.MatchString(line) || sslTrustedRe.MatchString(line) ||
				sslPreferRe.MatchString(line) || hstsRe.MatchString(line) {
				continue
			}

			// Modify listen directives to add SSL
			if listenRe.MatchString(line) && !strings.Contains(line, "ssl") {
				line = i.modifyListenDirective(line)
			}

			// Insert SSL config after the first listen directive in the block
			if listenRe.MatchString(line) && !sslConfigInserted {
				result = append(result, line)
				result = append(result, "")
				result = append(result, "    # SSL configuration managed by LCM")
				for _, sslLine := range strings.Split(strings.TrimRight(sslConfig, "\n"), "\n") {
					result = append(result, sslLine)
				}
				sslConfigInserted = true
				continue
			}
		}

		result = append(result, line)

		// Check if we're leaving the block
		if inBlock && blockBraces == 0 {
			inBlock = false
		}
	}

	return result
}

// modifyListenDirective adds SSL and optionally HTTP/2 to a listen directive
func (i *Installer) modifyListenDirective(line string) string {
	// Parse the listen directive - capture everything before the semicolon
	listenRe := regexp.MustCompile(`^(\s*listen\s+)([^;]+)(;.*)$`)
	matches := listenRe.FindStringSubmatch(line)
	if len(matches) < 4 {
		return line
	}

	prefix := matches[1]
	addrPortAndFlags := strings.TrimSpace(matches[2])
	ending := matches[3] // includes the semicolon

	// Split into address/port and existing flags
	parts := strings.Fields(addrPortAndFlags)
	if len(parts) == 0 {
		return line
	}

	addrPort := parts[0]
	existingFlags := parts[1:]

	// Change port 80 to 443
	if strings.HasSuffix(addrPort, ":80") {
		addrPort = strings.Replace(addrPort, ":80", ":443", 1)
	} else if addrPort == "80" {
		addrPort = "443"
	} else if !strings.Contains(addrPort, "443") && !strings.Contains(addrPort, ":") {
		// If it's just an IP or hostname without port, add 443
		addrPort = "443"
	}

	// Build new flags list
	newFlags := make([]string, 0, len(existingFlags)+2)
	hasSSL := false
	hasHTTP2 := false

	for _, flag := range existingFlags {
		if flag == "ssl" {
			hasSSL = true
		}
		if flag == "http2" {
			hasHTTP2 = true
		}
		newFlags = append(newFlags, flag)
	}

	// Add SSL flag if not present
	if !hasSSL {
		newFlags = append(newFlags, "ssl")
	}

	// Note: For nginx 1.25.1+, "listen ... http2" is deprecated
	// Use separate "http2 on;" directive instead (handled in generateSSLConfig)
	// We still add it here for backwards compatibility with older nginx
	if i.options.HTTP2 && !hasHTTP2 {
		newFlags = append(newFlags, "http2")
	}

	// Reconstruct the directive
	flagsStr := ""
	if len(newFlags) > 0 {
		flagsStr = " " + strings.Join(newFlags, " ")
	}

	return fmt.Sprintf("%s%s%s%s", prefix, addrPort, flagsStr, ending)
}

// createBackup creates a backup of a configuration file
func (i *Installer) createBackup(filePath string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.lcm-backup-%s", filePath, timestamp)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return "", err
	}

	return backupPath, nil
}

// restoreBackup restores a configuration file from backup
func (i *Installer) restoreBackup(filePath, backupPath string) error {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, content, 0644)
}

// CreateSSLSnippet creates a reusable SSL configuration snippet
func (i *Installer) CreateSSLSnippet(certPaths *storage.CertPaths, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(i.nginxInfo.ConfigDir, "snippets", "ssl-lcm.conf")
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create snippets directory: %w", err)
	}

	sslConfig := i.generateSSLConfig(certPaths)
	header := "# SSL configuration snippet managed by LCM\n# Include this file in your server blocks: include snippets/ssl-lcm.conf;\n\n"

	if err := os.WriteFile(outputPath, []byte(header+sslConfig), 0644); err != nil {
		return fmt.Errorf("failed to write SSL snippet: %w", err)
	}

	return nil
}

// Uninstall removes SSL configuration and restores HTTP
func (i *Installer) Uninstall(domains []string) error {
	// This is a simplified implementation
	// A full implementation would:
	// 1. Find server blocks for the domains
	// 2. Remove SSL directives
	// 3. Change listen 443 ssl back to listen 80
	// 4. Test and reload nginx
	return fmt.Errorf("uninstall not implemented yet")
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Summary returns a summary of the installation result
func (r *InstallResult) Summary() string {
	var sb strings.Builder

	if r.Success {
		sb.WriteString("✓ SSL installation completed successfully\n")
	} else {
		sb.WriteString("✗ SSL installation failed\n")
	}

	if len(r.Domains) > 0 {
		sb.WriteString(fmt.Sprintf("Domains: %s\n", strings.Join(r.Domains, ", ")))
	}

	if len(r.ModifiedFiles) > 0 {
		sb.WriteString("Modified files:\n")
		for _, f := range r.ModifiedFiles {
			sb.WriteString(fmt.Sprintf("  - %s\n", f))
		}
	}

	if len(r.BackupFiles) > 0 {
		sb.WriteString("Backup files:\n")
		for _, f := range r.BackupFiles {
			sb.WriteString(fmt.Sprintf("  - %s\n", f))
		}
	}

	if len(r.Warnings) > 0 {
		sb.WriteString("Warnings:\n")
		for _, w := range r.Warnings {
			sb.WriteString(fmt.Sprintf("  ⚠ %s\n", w))
		}
	}

	if len(r.Errors) > 0 {
		sb.WriteString("Errors:\n")
		for _, e := range r.Errors {
			sb.WriteString(fmt.Sprintf("  ✗ %s\n", e))
		}
	}

	return sb.String()
}
