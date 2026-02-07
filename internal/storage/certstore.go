package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertStore manages certificate storage with a certbot-like structure:
//
//	~/.tangra-client/
//	├── live/
//	│   └── <cert-name>/
//	│       ├── cert.pem       # Client certificate
//	│       ├── privkey.pem    # Private key
//	│       ├── chain.pem      # CA certificate chain
//	│       └── fullchain.pem  # Cert + chain concatenated
//	└── renewal/
//	    └── <cert-name>.json   # Certificate metadata
type CertStore struct {
	baseDir    string
	liveDir    string
	renewalDir string
}

// CertMetadata contains metadata about a stored certificate
type CertMetadata struct {
	Name              string    `json:"name"`
	CommonName        string    `json:"common_name"`
	SerialNumber      string    `json:"serial_number"`
	Fingerprint       string    `json:"fingerprint,omitempty"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	LastUpdated       time.Time `json:"last_updated"`
	IssuerName        string    `json:"issuer_name,omitempty"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	IPAddresses       []string  `json:"ip_addresses,omitempty"`
	PreviousSerial    string    `json:"previous_serial,omitempty"`
	RenewalCount      int       `json:"renewal_count"`
	LastHookExecution time.Time `json:"last_hook_execution,omitempty"`
}

// CertPaths contains the file paths for a certificate
type CertPaths struct {
	CertFile      string
	PrivKeyFile   string
	ChainFile     string
	FullChainFile string
	MetadataFile  string
}

// NewCertStore creates a new certificate store
func NewCertStore(baseDir string) (*CertStore, error) {
	expandedDir, err := expandPath(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to expand path: %w", err)
	}

	store := &CertStore{
		baseDir:    expandedDir,
		liveDir:    filepath.Join(expandedDir, "live"),
		renewalDir: filepath.Join(expandedDir, "renewal"),
	}

	if err := os.MkdirAll(store.liveDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create live directory: %w", err)
	}
	if err := os.MkdirAll(store.renewalDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create renewal directory: %w", err)
	}

	return store, nil
}

// GetPaths returns the paths for a certificate by name
func (s *CertStore) GetPaths(certName string) *CertPaths {
	certDir := filepath.Join(s.liveDir, certName)
	return &CertPaths{
		CertFile:      filepath.Join(certDir, "cert.pem"),
		PrivKeyFile:   filepath.Join(certDir, "privkey.pem"),
		ChainFile:     filepath.Join(certDir, "chain.pem"),
		FullChainFile: filepath.Join(certDir, "fullchain.pem"),
		MetadataFile:  filepath.Join(s.renewalDir, certName+".json"),
	}
}

// SaveCertificate stores a certificate and its components
func (s *CertStore) SaveCertificate(certName string, certPEM, keyPEM, chainPEM string, metadata *CertMetadata) error {
	certDir := filepath.Join(s.liveDir, certName)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	paths := s.GetPaths(certName)

	if certPEM != "" {
		if err := os.WriteFile(paths.CertFile, []byte(certPEM), 0600); err != nil {
			return fmt.Errorf("failed to write certificate: %w", err)
		}
	}

	if keyPEM != "" {
		if err := os.WriteFile(paths.PrivKeyFile, []byte(keyPEM), 0600); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
	}

	if chainPEM != "" {
		if err := os.WriteFile(paths.ChainFile, []byte(chainPEM), 0644); err != nil {
			return fmt.Errorf("failed to write chain: %w", err)
		}

		if certPEM != "" {
			fullchain := certPEM
			if !strings.HasSuffix(certPEM, "\n") {
				fullchain += "\n"
			}
			fullchain += chainPEM
			if err := os.WriteFile(paths.FullChainFile, []byte(fullchain), 0600); err != nil {
				return fmt.Errorf("failed to write fullchain: %w", err)
			}
		}
	}

	if metadata != nil {
		metadata.Name = certName
		metadata.LastUpdated = time.Now()
		metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		if err := os.WriteFile(paths.MetadataFile, metadataBytes, 0644); err != nil {
			return fmt.Errorf("failed to write metadata: %w", err)
		}
	}

	return nil
}

// LoadMetadata loads certificate metadata
func (s *CertStore) LoadMetadata(certName string) (*CertMetadata, error) {
	paths := s.GetPaths(certName)

	data, err := os.ReadFile(paths.MetadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata CertMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, nil
}

// UpdateMetadata updates the metadata for a certificate
func (s *CertStore) UpdateMetadata(certName string, updateFn func(*CertMetadata)) error {
	metadata, err := s.LoadMetadata(certName)
	if err != nil {
		return err
	}
	if metadata == nil {
		metadata = &CertMetadata{Name: certName}
	}

	updateFn(metadata)
	metadata.LastUpdated = time.Now()

	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	paths := s.GetPaths(certName)
	if err := os.WriteFile(paths.MetadataFile, metadataBytes, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	return nil
}

// ListCertificates returns all stored certificate names
func (s *CertStore) ListCertificates() ([]string, error) {
	entries, err := os.ReadDir(s.liveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names, nil
}

// CertificateExists checks if a certificate exists by name
func (s *CertStore) CertificateExists(certName string) bool {
	paths := s.GetPaths(certName)
	_, err := os.Stat(paths.CertFile)
	return err == nil
}

// DeleteCertificate removes a certificate and its metadata
func (s *CertStore) DeleteCertificate(certName string) error {
	certDir := filepath.Join(s.liveDir, certName)
	if err := os.RemoveAll(certDir); err != nil {
		return fmt.Errorf("failed to remove certificate directory: %w", err)
	}

	paths := s.GetPaths(certName)
	if err := os.Remove(paths.MetadataFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove metadata: %w", err)
	}

	return nil
}

// GetAllMetadata returns metadata for all stored certificates
func (s *CertStore) GetAllMetadata() ([]*CertMetadata, error) {
	names, err := s.ListCertificates()
	if err != nil {
		return nil, err
	}

	var allMetadata []*CertMetadata
	for _, name := range names {
		metadata, err := s.LoadMetadata(name)
		if err != nil {
			continue
		}
		if metadata != nil {
			allMetadata = append(allMetadata, metadata)
		}
	}

	return allMetadata, nil
}

// LoadPrivateKey loads a private key's PEM content
func (s *CertStore) LoadPrivateKey(certName string) (string, error) {
	paths := s.GetPaths(certName)
	data, err := os.ReadFile(paths.PrivKeyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}
	return string(data), nil
}

// BaseDir returns the base directory of the store
func (s *CertStore) BaseDir() string {
	return s.baseDir
}

func expandPath(path string) (string, error) {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	} else if path == "~" {
		return os.UserHomeDir()
	}
	return path, nil
}
