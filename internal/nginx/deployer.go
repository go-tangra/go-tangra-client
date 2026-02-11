package nginx

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-client/internal/storage"
)

// DeployResult contains the result of a daemon-mode certificate deployment to nginx
type DeployResult struct {
	ModifiedFiles  []string
	BackupFiles    []string
	UpdatedDomains []string
	Reloaded       bool
	Errors         []string
}

// Deployer handles automatic certificate deployment to nginx server blocks
// in daemon mode. It finds matching SSL-enabled vhosts, updates cert/key paths,
// tests the config, and reloads nginx.
type Deployer struct {
	nginxInfo *NginxInfo
	options  *InstallOptions
}

// NewDeployer creates a new nginx certificate deployer for daemon mode
func NewDeployer(info *NginxInfo, opts *InstallOptions) *Deployer {
	if opts == nil {
		opts = DefaultInstallOptions()
	}
	return &Deployer{
		nginxInfo: info,
		options:  opts,
	}
}

// DeployCertificate finds SSL-enabled nginx server blocks matching the given domains,
// updates their ssl_certificate / ssl_certificate_key paths (and optional SSL directives),
// tests the config, and reloads nginx. HTTP-only vhosts are not converted to HTTPS.
func (d *Deployer) DeployCertificate(store *storage.CertStore, certName string, domains []string) *DeployResult {
	result := &DeployResult{}

	if len(domains) == 0 {
		result.Errors = append(result.Errors, "no domains provided")
		return result
	}

	// Re-parse config each time (configs may change between deploys)
	parsedConfig, err := ParseConfig(d.nginxInfo)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse nginx config: %v", err))
		return result
	}

	certPaths := store.GetPaths(certName)

	// Collect unique SSL-enabled blocks matching the domains
	type blockEntry struct {
		block   *ServerBlock
		domains []string
	}
	seen := make(map[string]int) // filePath:lineStart -> index in entries
	var entries []blockEntry

	for _, domain := range domains {
		block := parsedConfig.FindServerBlockByDomain(domain)
		if block == nil {
			continue
		}

		// Only deploy to SSL-enabled blocks
		if !block.SSLEnabled {
			continue
		}

		// Skip if cert path already points to the correct file
		if block.SSLCertPath == certPaths.FullChainFile {
			continue
		}

		key := fmt.Sprintf("%s:%d", block.FilePath, block.LineStart)
		if idx, ok := seen[key]; ok {
			entries[idx].domains = append(entries[idx].domains, domain)
		} else {
			seen[key] = len(entries)
			entries = append(entries, blockEntry{block: block, domains: []string{domain}})
		}
	}

	if len(entries) == 0 {
		return result
	}

	// Generate SSL config directives (reuses Installer pattern)
	sslDirectives := d.generateSSLDirectives(certPaths)

	// Update each block
	for _, entry := range entries {
		if err := d.updateServerBlock(entry.block, certPaths, sslDirectives, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to update %s (lines %d-%d): %v",
				entry.block.FilePath, entry.block.LineStart, entry.block.LineEnd, err))
		} else {
			result.UpdatedDomains = append(result.UpdatedDomains, entry.domains...)
		}
	}

	if len(result.ModifiedFiles) == 0 {
		return result
	}

	// Test nginx configuration
	if err := d.nginxInfo.TestConfig(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("nginx config test failed: %v", err))
		// Restore all backups
		for i, modFile := range result.ModifiedFiles {
			if i < len(result.BackupFiles) {
				if restoreErr := restoreFromBackup(modFile, result.BackupFiles[i]); restoreErr != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("failed to restore backup %s: %v", result.BackupFiles[i], restoreErr))
				}
			}
		}
		return result
	}

	// Reload nginx
	if err := d.nginxInfo.Reload(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("nginx reload failed: %v", err))
	} else {
		result.Reloaded = true
	}

	return result
}

// updateServerBlock backs up the config file, then replaces ssl_certificate and
// ssl_certificate_key directives (and optional SSL settings) within the block's line range.
func (d *Deployer) updateServerBlock(block *ServerBlock, certPaths *storage.CertPaths, sslDirectives map[string]string, result *DeployResult) error {
	content, err := os.ReadFile(block.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", block.FilePath, err)
	}

	// Create backup
	backupPath, err := createDeployBackup(block.FilePath)
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	result.BackupFiles = append(result.BackupFiles, backupPath)

	lines := strings.Split(string(content), "\n")

	// Regex patterns for directives we replace
	sslCertRe := regexp.MustCompile(`^(\s*)ssl_certificate\s+`)
	sslKeyRe := regexp.MustCompile(`^(\s*)ssl_certificate_key\s+`)
	sslProtocolsRe := regexp.MustCompile(`^(\s*)ssl_protocols\s+`)
	sslCiphersRe := regexp.MustCompile(`^(\s*)ssl_ciphers\s+`)
	sslSessionTimeoutRe := regexp.MustCompile(`^(\s*)ssl_session_timeout\s+`)
	sslSessionCacheRe := regexp.MustCompile(`^(\s*)ssl_session_cache\s+`)
	sslSessionTicketsRe := regexp.MustCompile(`^(\s*)ssl_session_tickets\s+`)
	sslStaplingRe := regexp.MustCompile(`^(\s*)ssl_stapling\s+`)
	sslStaplingVerifyRe := regexp.MustCompile(`^(\s*)ssl_stapling_verify\s+`)
	sslTrustedRe := regexp.MustCompile(`^(\s*)ssl_trusted_certificate\s+`)
	sslDHParamRe := regexp.MustCompile(`^(\s*)ssl_dhparam\s+`)
	sslPreferRe := regexp.MustCompile(`^(\s*)ssl_prefer_server_ciphers\s+`)
	hstsRe := regexp.MustCompile(`^(\s*)add_header\s+Strict-Transport-Security\s+`)

	// Track which directives we've replaced vs. need to insert
	replaced := make(map[string]bool)
	nestedBraces := 0
	certLineInserted := false

	result.ModifiedFiles = append(result.ModifiedFiles, block.FilePath)

	modified := make([]string, 0, len(lines))
	for i, line := range lines {
		lineNum := i + 1 // 1-indexed

		if lineNum < block.LineStart || lineNum > block.LineEnd {
			modified = append(modified, line)
			continue
		}

		// Track nested braces within the block
		stripped := stripComment(line)
		nestedBraces += strings.Count(stripped, "{") - strings.Count(stripped, "}")

		// Only replace directives at the server block level (nestedBraces == 1)
		if nestedBraces > 1 {
			modified = append(modified, line)
			continue
		}

		// Replace ssl_certificate
		if m := sslCertRe.FindStringSubmatch(stripped); m != nil {
			indent := m[1]
			modified = append(modified, fmt.Sprintf("%sssl_certificate %s;", indent, certPaths.FullChainFile))
			replaced["ssl_certificate"] = true
			// After replacing cert line, insert any remaining SSL directives
			// that don't already exist in the block
			if !certLineInserted {
				certLineInserted = true
				indent := m[1]
				d.insertMissingDirectives(indent, sslDirectives, replaced, &modified, lines, block)
			}
			continue
		}

		// Replace ssl_certificate_key
		if m := sslKeyRe.FindStringSubmatch(stripped); m != nil {
			indent := m[1]
			modified = append(modified, fmt.Sprintf("%sssl_certificate_key %s;", indent, certPaths.PrivKeyFile))
			replaced["ssl_certificate_key"] = true
			continue
		}

		// Replace other SSL directives if configured
		if m := sslProtocolsRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_protocols"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_protocols %s;", m[1], sslDirectives["ssl_protocols"]))
			replaced["ssl_protocols"] = true
			continue
		}
		if m := sslCiphersRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_ciphers"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_ciphers %s;", m[1], sslDirectives["ssl_ciphers"]))
			replaced["ssl_ciphers"] = true
			continue
		}
		if m := sslPreferRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_prefer_server_ciphers"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_prefer_server_ciphers %s;", m[1], sslDirectives["ssl_prefer_server_ciphers"]))
			replaced["ssl_prefer_server_ciphers"] = true
			continue
		}
		if m := sslDHParamRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_dhparam"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_dhparam %s;", m[1], sslDirectives["ssl_dhparam"]))
			replaced["ssl_dhparam"] = true
			continue
		}
		if m := sslSessionTimeoutRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_session_timeout"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_session_timeout %s;", m[1], sslDirectives["ssl_session_timeout"]))
			replaced["ssl_session_timeout"] = true
			continue
		}
		if m := sslSessionCacheRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_session_cache"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_session_cache %s;", m[1], sslDirectives["ssl_session_cache"]))
			replaced["ssl_session_cache"] = true
			continue
		}
		if m := sslSessionTicketsRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_session_tickets"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_session_tickets %s;", m[1], sslDirectives["ssl_session_tickets"]))
			replaced["ssl_session_tickets"] = true
			continue
		}
		if m := sslStaplingRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_stapling"] != "" && !sslStaplingVerifyRe.MatchString(stripped) {
			modified = append(modified, fmt.Sprintf("%sssl_stapling %s;", m[1], sslDirectives["ssl_stapling"]))
			replaced["ssl_stapling"] = true
			continue
		}
		if m := sslStaplingVerifyRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_stapling_verify"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_stapling_verify %s;", m[1], sslDirectives["ssl_stapling_verify"]))
			replaced["ssl_stapling_verify"] = true
			continue
		}
		if m := sslTrustedRe.FindStringSubmatch(stripped); m != nil && sslDirectives["ssl_trusted_certificate"] != "" {
			modified = append(modified, fmt.Sprintf("%sssl_trusted_certificate %s;", m[1], sslDirectives["ssl_trusted_certificate"]))
			replaced["ssl_trusted_certificate"] = true
			continue
		}
		if m := hstsRe.FindStringSubmatch(stripped); m != nil && sslDirectives["hsts"] != "" {
			modified = append(modified, fmt.Sprintf("%sadd_header Strict-Transport-Security %s always;", m[1], sslDirectives["hsts"]))
			replaced["hsts"] = true
			continue
		}

		modified = append(modified, line)
	}

	if err := os.WriteFile(block.FilePath, []byte(strings.Join(modified, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", block.FilePath, err)
	}

	return nil
}

// insertMissingDirectives adds SSL directives that were configured but not found
// in the existing block (so there's nothing to replace). They are inserted after
// the ssl_certificate line.
func (d *Deployer) insertMissingDirectives(indent string, directives map[string]string, replaced map[string]bool, modified *[]string, lines []string, block *ServerBlock) {
	// Check which directives exist in the block (even if we haven't processed them yet)
	existing := d.scanExistingDirectives(lines, block)

	// Insert directives that aren't already present in the block
	insertOrder := []struct {
		key      string
		template string
	}{
		{"ssl_protocols", "%sssl_protocols %s;"},
		{"ssl_ciphers", "%sssl_ciphers %s;"},
		{"ssl_prefer_server_ciphers", "%sssl_prefer_server_ciphers %s;"},
		{"ssl_dhparam", "%sssl_dhparam %s;"},
		{"ssl_session_timeout", "%sssl_session_timeout %s;"},
		{"ssl_session_cache", "%sssl_session_cache %s;"},
		{"ssl_session_tickets", "%sssl_session_tickets %s;"},
		{"ssl_stapling", "%sssl_stapling %s;"},
		{"ssl_stapling_verify", "%sssl_stapling_verify %s;"},
		{"ssl_trusted_certificate", "%sssl_trusted_certificate %s;"},
		{"hsts", "%sadd_header Strict-Transport-Security %s always;"},
	}

	for _, item := range insertOrder {
		val := directives[item.key]
		if val == "" {
			continue
		}
		if existing[item.key] || replaced[item.key] {
			continue
		}
		*modified = append(*modified, fmt.Sprintf(item.template, indent, val))
		replaced[item.key] = true
	}
}

// scanExistingDirectives scans lines within a block to identify which SSL directives
// already exist, so we don't double-insert them.
func (d *Deployer) scanExistingDirectives(lines []string, block *ServerBlock) map[string]bool {
	found := make(map[string]bool)
	patterns := map[string]*regexp.Regexp{
		"ssl_protocols":              regexp.MustCompile(`^\s*ssl_protocols\s+`),
		"ssl_ciphers":               regexp.MustCompile(`^\s*ssl_ciphers\s+`),
		"ssl_prefer_server_ciphers": regexp.MustCompile(`^\s*ssl_prefer_server_ciphers\s+`),
		"ssl_dhparam":               regexp.MustCompile(`^\s*ssl_dhparam\s+`),
		"ssl_session_timeout":       regexp.MustCompile(`^\s*ssl_session_timeout\s+`),
		"ssl_session_cache":         regexp.MustCompile(`^\s*ssl_session_cache\s+`),
		"ssl_session_tickets":       regexp.MustCompile(`^\s*ssl_session_tickets\s+`),
		"ssl_stapling":              regexp.MustCompile(`^\s*ssl_stapling\s+`),
		"ssl_stapling_verify":       regexp.MustCompile(`^\s*ssl_stapling_verify\s+`),
		"ssl_trusted_certificate":   regexp.MustCompile(`^\s*ssl_trusted_certificate\s+`),
		"hsts":                      regexp.MustCompile(`^\s*add_header\s+Strict-Transport-Security\s+`),
	}

	for i, line := range lines {
		lineNum := i + 1
		if lineNum < block.LineStart || lineNum > block.LineEnd {
			continue
		}
		stripped := stripComment(line)
		for key, re := range patterns {
			if re.MatchString(stripped) {
				found[key] = true
			}
		}
	}
	return found
}

// generateSSLDirectives builds a map of directive name -> value for SSL settings
// based on the deployer's options. Only non-empty values are included.
func (d *Deployer) generateSSLDirectives(certPaths *storage.CertPaths) map[string]string {
	directives := make(map[string]string)

	if d.options.SSLProtocols != "" {
		directives["ssl_protocols"] = d.options.SSLProtocols
	}
	if d.options.SSLCiphers != "" {
		directives["ssl_ciphers"] = d.options.SSLCiphers
		directives["ssl_prefer_server_ciphers"] = "on"
	}
	if d.options.DHParamPath != "" {
		directives["ssl_dhparam"] = d.options.DHParamPath
	}

	directives["ssl_session_timeout"] = "1d"
	directives["ssl_session_cache"] = "shared:SSL:50m"
	directives["ssl_session_tickets"] = "off"

	if d.options.OCSPStapling {
		directives["ssl_stapling"] = "on"
		directives["ssl_stapling_verify"] = "on"
		if certPaths.ChainFile != "" {
			directives["ssl_trusted_certificate"] = certPaths.ChainFile
		}
	}

	if d.options.HSTS {
		maxAge := d.options.HSTSMaxAge
		if maxAge == 0 {
			maxAge = 31536000
		}
		directives["hsts"] = fmt.Sprintf("\"max-age=%d; includeSubDomains\"", maxAge)
	}

	return directives
}

// stripComment removes the comment portion of an nginx config line
func stripComment(line string) string {
	before, _, _ := strings.Cut(line, "#")
	return before
}

// createDeployBackup creates a timestamped backup of a config file
func createDeployBackup(filePath string) (string, error) {
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

// restoreFromBackup restores a config file from its backup
func restoreFromBackup(filePath, backupPath string) error {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, content, 0644)
}

// Summary returns a human-readable summary of the deploy result
func (r *DeployResult) Summary() string {
	var sb strings.Builder

	if len(r.UpdatedDomains) > 0 {
		fmt.Fprintf(&sb, "    Nginx: updated %d domain(s): %s\n",
			len(r.UpdatedDomains), strings.Join(r.UpdatedDomains, ", "))
	}
	if len(r.ModifiedFiles) > 0 {
		for _, f := range r.ModifiedFiles {
			fmt.Fprintf(&sb, "    Nginx: modified %s\n", f)
		}
	}
	if r.Reloaded {
		sb.WriteString("    Nginx: config tested OK, reloaded\n")
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&sb, "    Nginx: ERROR: %s\n", e)
	}

	return sb.String()
}
