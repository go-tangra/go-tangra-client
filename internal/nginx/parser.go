package nginx

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ServerBlock represents an nginx server block configuration
type ServerBlock struct {
	FilePath    string
	LineStart   int
	LineEnd     int
	ServerNames []string
	Listen      []ListenDirective
	SSLEnabled  bool
	SSLCertPath string
	SSLKeyPath  string
	Root        string
	Index       string
	RawContent  string
	IsHTTPS     bool
	IsDefault   bool
}

// ListenDirective represents a listen directive
type ListenDirective struct {
	Address  string
	Port     int
	SSL      bool
	HTTP2    bool
	Default  bool
	IPv6     bool
	RawValue string
}

// ParsedConfig contains all parsed server blocks from nginx configuration
type ParsedConfig struct {
	ServerBlocks []*ServerBlock
	ConfigFiles  []string
}

// ParseConfig parses nginx configuration and extracts server blocks
func ParseConfig(info *NginxInfo) (*ParsedConfig, error) {
	files, err := info.GetIncludedFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get config files: %w", err)
	}

	parsed := &ParsedConfig{
		ConfigFiles: files,
	}

	for _, file := range files {
		blocks, err := parseServerBlocks(file)
		if err != nil {
			// Log but continue with other files
			continue
		}
		parsed.ServerBlocks = append(parsed.ServerBlocks, blocks...)
	}

	return parsed, nil
}

// parseServerBlocks extracts server blocks from a single configuration file
func parseServerBlocks(filePath string) ([]*ServerBlock, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var blocks []*ServerBlock
	var currentBlock *ServerBlock
	var blockContent strings.Builder
	braceCount := 0
	inServerBlock := false
	lineNum := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Remove comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}

		// Check for server block start
		if !inServerBlock && strings.Contains(line, "server") && strings.Contains(line, "{") {
			inServerBlock = true
			currentBlock = &ServerBlock{
				FilePath:  filePath,
				LineStart: lineNum,
			}
			blockContent.Reset()
			braceCount = strings.Count(line, "{") - strings.Count(line, "}")
			blockContent.WriteString(line)
			blockContent.WriteString("\n")

			if braceCount == 0 {
				// Single-line block (unlikely but handle it)
				currentBlock.LineEnd = lineNum
				currentBlock.RawContent = blockContent.String()
				parseServerBlockContent(currentBlock)
				blocks = append(blocks, currentBlock)
				inServerBlock = false
				currentBlock = nil
			}
			continue
		}

		if inServerBlock {
			blockContent.WriteString(line)
			blockContent.WriteString("\n")
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			if braceCount == 0 {
				currentBlock.LineEnd = lineNum
				currentBlock.RawContent = blockContent.String()
				parseServerBlockContent(currentBlock)
				blocks = append(blocks, currentBlock)
				inServerBlock = false
				currentBlock = nil
			}
		}
	}

	return blocks, scanner.Err()
}

// parseServerBlockContent parses directives within a server block
func parseServerBlockContent(block *ServerBlock) {
	lines := strings.Split(block.RawContent, "\n")

	// Regular expressions for parsing
	serverNameRe := regexp.MustCompile(`^\s*server_name\s+(.+?);`)
	listenRe := regexp.MustCompile(`^\s*listen\s+(.+?);`)
	sslCertRe := regexp.MustCompile(`^\s*ssl_certificate\s+(.+?);`)
	sslKeyRe := regexp.MustCompile(`^\s*ssl_certificate_key\s+(.+?);`)
	sslOnRe := regexp.MustCompile(`^\s*ssl\s+on;`)
	rootRe := regexp.MustCompile(`^\s*root\s+(.+?);`)
	indexRe := regexp.MustCompile(`^\s*index\s+(.+?);`)

	nestedBraces := 0

	for _, line := range lines {
		// Track nested blocks (location, if, etc.)
		nestedBraces += strings.Count(line, "{") - strings.Count(line, "}")

		// Only parse directives at the server block level (not nested)
		if nestedBraces > 1 {
			continue
		}

		// Parse server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) > 1 {
			names := strings.Fields(matches[1])
			for _, name := range names {
				if name != "" && name != "_" {
					block.ServerNames = append(block.ServerNames, name)
				}
				if name == "_" {
					block.IsDefault = true
				}
			}
		}

		// Parse listen directive
		if matches := listenRe.FindStringSubmatch(line); len(matches) > 1 {
			listen := parseListenDirective(matches[1])
			block.Listen = append(block.Listen, listen)
			if listen.SSL {
				block.SSLEnabled = true
				block.IsHTTPS = true
			}
			if listen.Default {
				block.IsDefault = true
			}
		}

		// Parse ssl_certificate
		if matches := sslCertRe.FindStringSubmatch(line); len(matches) > 1 {
			block.SSLCertPath = strings.TrimSpace(matches[1])
			block.SSLEnabled = true
			block.IsHTTPS = true
		}

		// Parse ssl_certificate_key
		if matches := sslKeyRe.FindStringSubmatch(line); len(matches) > 1 {
			block.SSLKeyPath = strings.TrimSpace(matches[1])
		}

		// Parse ssl on; (legacy)
		if sslOnRe.MatchString(line) {
			block.SSLEnabled = true
			block.IsHTTPS = true
		}

		// Parse root
		if matches := rootRe.FindStringSubmatch(line); len(matches) > 1 {
			block.Root = strings.TrimSpace(matches[1])
		}

		// Parse index
		if matches := indexRe.FindStringSubmatch(line); len(matches) > 1 {
			block.Index = strings.TrimSpace(matches[1])
		}
	}

	// Determine if HTTPS based on listen ports
	for _, l := range block.Listen {
		if l.Port == 443 {
			block.IsHTTPS = true
		}
	}
}

// parseListenDirective parses a listen directive value
func parseListenDirective(value string) ListenDirective {
	listen := ListenDirective{
		RawValue: value,
	}

	parts := strings.Fields(value)
	if len(parts) == 0 {
		return listen
	}

	// Parse address:port or just port
	addrPort := parts[0]

	// Check for IPv6
	if strings.HasPrefix(addrPort, "[") {
		listen.IPv6 = true
		// [::]:80 or [::1]:80
		if idx := strings.LastIndex(addrPort, "]:"); idx >= 0 {
			listen.Address = addrPort[:idx+1]
			if port, err := strconv.Atoi(addrPort[idx+2:]); err == nil {
				listen.Port = port
			}
		} else if strings.HasSuffix(addrPort, "]") {
			listen.Address = addrPort
			listen.Port = 80 // default
		}
	} else if strings.Contains(addrPort, ":") {
		// address:port
		parts := strings.Split(addrPort, ":")
		if len(parts) == 2 {
			listen.Address = parts[0]
			if port, err := strconv.Atoi(parts[1]); err == nil {
				listen.Port = port
			}
		}
	} else {
		// Just port
		if port, err := strconv.Atoi(addrPort); err == nil {
			listen.Port = port
		}
	}

	// Parse additional options
	for _, part := range parts[1:] {
		switch strings.ToLower(part) {
		case "ssl":
			listen.SSL = true
		case "http2":
			listen.HTTP2 = true
		case "default_server", "default":
			listen.Default = true
		}
	}

	return listen
}

// FindServerBlockByDomain finds a server block that handles a specific domain
func (p *ParsedConfig) FindServerBlockByDomain(domain string) *ServerBlock {
	for _, block := range p.ServerBlocks {
		for _, name := range block.ServerNames {
			// Exact match
			if name == domain {
				return block
			}
			// Wildcard match
			if strings.HasPrefix(name, "*.") {
				suffix := name[1:] // Remove *
				if strings.HasSuffix(domain, suffix) {
					return block
				}
			}
			// Regex match (simplified)
			if strings.HasPrefix(name, "~") {
				// Skip regex for now, too complex
				continue
			}
		}
	}
	return nil
}

// FindHTTPServerBlocks returns server blocks that listen on port 80
func (p *ParsedConfig) FindHTTPServerBlocks() []*ServerBlock {
	var blocks []*ServerBlock
	for _, block := range p.ServerBlocks {
		for _, listen := range block.Listen {
			if listen.Port == 80 || (listen.Port == 0 && !listen.SSL) {
				blocks = append(blocks, block)
				break
			}
		}
	}
	return blocks
}

// FindHTTPSServerBlocks returns server blocks that listen on port 443 or have SSL
func (p *ParsedConfig) FindHTTPSServerBlocks() []*ServerBlock {
	var blocks []*ServerBlock
	for _, block := range p.ServerBlocks {
		if block.SSLEnabled || block.IsHTTPS {
			blocks = append(blocks, block)
			continue
		}
		for _, listen := range block.Listen {
			if listen.Port == 443 || listen.SSL {
				blocks = append(blocks, block)
				break
			}
		}
	}
	return blocks
}

// GetAllDomains returns all unique domain names from all server blocks
func (p *ParsedConfig) GetAllDomains() []string {
	domainSet := make(map[string]bool)
	var domains []string

	for _, block := range p.ServerBlocks {
		for _, name := range block.ServerNames {
			// Skip wildcards and special names
			if strings.HasPrefix(name, "*.") || strings.HasPrefix(name, "~") || name == "_" || name == "" {
				continue
			}
			// Skip localhost variants
			if name == "localhost" || strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".localhost") {
				continue
			}
			if !domainSet[name] {
				domainSet[name] = true
				domains = append(domains, name)
			}
		}
	}

	return domains
}

// String returns a summary of the server block
func (block *ServerBlock) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("File: %s (lines %d-%d)\n", block.FilePath, block.LineStart, block.LineEnd))
	if len(block.ServerNames) > 0 {
		sb.WriteString(fmt.Sprintf("  Server Names: %s\n", strings.Join(block.ServerNames, ", ")))
	}
	for _, l := range block.Listen {
		sb.WriteString(fmt.Sprintf("  Listen: %s\n", l.RawValue))
	}
	if block.SSLEnabled {
		sb.WriteString("  SSL: enabled\n")
		if block.SSLCertPath != "" {
			sb.WriteString(fmt.Sprintf("    Certificate: %s\n", block.SSLCertPath))
		}
		if block.SSLKeyPath != "" {
			sb.WriteString(fmt.Sprintf("    Key: %s\n", block.SSLKeyPath))
		}
	}
	return sb.String()
}
