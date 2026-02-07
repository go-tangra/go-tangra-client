package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DeviceState persists IPAM device state between syncs
type DeviceState struct {
	DeviceID     string            `json:"device_id"`
	TenantID     uint32            `json:"tenant_id"`
	LastSyncTime time.Time         `json:"last_sync_time"`
	LastHostInfo *HostInfoSnapshot `json:"last_host_info"`
}

// HostInfoSnapshot is a serializable snapshot of host info for change detection
type HostInfoSnapshot struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Distro       string   `json:"distro"`
	Kernel       string   `json:"kernel"`
	CPUModel     string   `json:"cpu_model"`
	PrimaryIP    string   `json:"primary_ip"`
	CPUCount     int      `json:"cpu_count"`
	DiskCount    int      `json:"disk_count"`
	MemoryTotal  uint64   `json:"memory_total"`
	MACAddresses []string `json:"mac_addresses"`
	IsVM         bool     `json:"is_vm"`
	IsContainer  bool     `json:"is_container"`
}

// StateStore manages IPAM device state persistence
type StateStore struct {
	stateFile string
}

// NewStateStore creates a new state store
func NewStateStore(configDir string) *StateStore {
	return &StateStore{
		stateFile: filepath.Join(configDir, "state.json"),
	}
}

// Load reads the device state from disk
func (s *StateStore) Load() (*DeviceState, error) {
	data, err := os.ReadFile(s.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state DeviceState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}

	return &state, nil
}

// Save writes the device state to disk
func (s *StateStore) Save(state *DeviceState) error {
	dir := filepath.Dir(s.stateFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(s.stateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}
