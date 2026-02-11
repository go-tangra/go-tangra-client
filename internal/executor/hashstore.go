package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ApprovedHash stores the approved hash for a script.
type ApprovedHash struct {
	Hash       string    `json:"hash"`
	ApprovedAt time.Time `json:"approved_at"`
}

// HashStore manages locally approved script content hashes.
// File: {config-dir}/approved_hashes.json
type HashStore struct {
	mu       sync.RWMutex
	filePath string
	hashes   map[string]ApprovedHash
}

// NewHashStore creates a new hash store at the given config directory.
func NewHashStore(configDir string) *HashStore {
	return &HashStore{
		filePath: filepath.Join(configDir, "approved_hashes.json"),
		hashes:   make(map[string]ApprovedHash),
	}
}

// Load reads the hash store from disk.
func (s *HashStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.hashes = make(map[string]ApprovedHash)
			return nil
		}
		return fmt.Errorf("failed to read hash store: %w", err)
	}

	var hashes map[string]ApprovedHash
	if err := json.Unmarshal(data, &hashes); err != nil {
		return fmt.Errorf("failed to parse hash store: %w", err)
	}

	s.hashes = hashes
	return nil
}

// Save writes the hash store to disk.
func (s *HashStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s.hashes, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal hash store: %w", err)
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.WriteFile(s.filePath, data, 0600)
}

// IsApproved checks if the given script ID and hash are approved.
func (s *HashStore) IsApproved(scriptID, hash string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.hashes[scriptID]
	if !ok {
		return false
	}
	return entry.Hash == hash
}

// GetHash returns the stored hash for a script ID, or empty string if not found.
func (s *HashStore) GetHash(scriptID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.hashes[scriptID]
	if !ok {
		return ""
	}
	return entry.Hash
}

// Approve stores the hash for a script ID and saves to disk.
func (s *HashStore) Approve(scriptID, hash string) error {
	s.mu.Lock()
	s.hashes[scriptID] = ApprovedHash{
		Hash:       hash,
		ApprovedAt: time.Now(),
	}
	s.mu.Unlock()

	return s.Save()
}

// Remove deletes the hash for a script ID.
func (s *HashStore) Remove(scriptID string) error {
	s.mu.Lock()
	delete(s.hashes, scriptID)
	s.mu.Unlock()

	return s.Save()
}
