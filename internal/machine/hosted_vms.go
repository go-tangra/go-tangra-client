package machine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// HostedVM describes a guest (QEMU VM or LXC container) hosted on this machine,
// as declared in the Proxmox VE config files. It is used by IPAM to build the
// VM -> hypervisor-host "Connected To" topology: the guest's NIC MAC is matched
// against the host's reported hosted VMs.
type HostedVM struct {
	VMID string   `json:"vmid"`           // numeric guest id, e.g. "101"
	Name string   `json:"name,omitempty"` // guest name/hostname if declared
	Type string   `json:"type"`           // "qemu" or "lxc"
	MACs []string `json:"macs"`           // lowercased NIC MAC addresses
}

const (
	pveQemuDir = "/etc/pve/qemu-server"
	pveLxcDir  = "/etc/pve/lxc"
)

// macRe matches a colon-separated MAC address anywhere in a config line.
var macRe = regexp.MustCompile(`(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b`)

// getHostedVMs reads the Proxmox VE guest configs on this host and returns the
// declared VMs/containers with their NIC MACs. Returns nil on a non-Proxmox host
// (the config directories simply do not exist). Best-effort: an unreadable or
// malformed config file is skipped, never fatal.
func getHostedVMs() []HostedVM {
	var out []HostedVM
	out = append(out, readPVEConfigs(pveQemuDir, "qemu", "name:")...)
	out = append(out, readPVEConfigs(pveLxcDir, "lxc", "hostname:")...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// readPVEConfigs parses every "<vmid>.conf" in dir. nameKey is the config key
// holding the guest's display name ("name:" for QEMU, "hostname:" for LXC).
func readPVEConfigs(dir, guestType, nameKey string) []HostedVM {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []HostedVM
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		vmid := strings.TrimSuffix(e.Name(), ".conf")
		if vmid == "" {
			continue
		}
		vm := parseGuestConfig(filepath.Join(dir, e.Name()), vmid, guestType, nameKey)
		if len(vm.MACs) > 0 {
			out = append(out, vm)
		}
	}
	return out
}

// parseGuestConfig extracts the guest name and NIC MACs from a single PVE config
// file. Only the active section (before any "[snapshot]" header) is considered.
func parseGuestConfig(path, vmid, guestType, nameKey string) HostedVM {
	vm := HostedVM{VMID: vmid, Type: guestType}
	data, err := os.ReadFile(path)
	if err != nil {
		return vm
	}
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// Snapshots are appended as "[snapname]" sections; stop at the first one
		// so we only report the live configuration.
		if strings.HasPrefix(line, "[") {
			break
		}
		if vm.Name == "" && strings.HasPrefix(line, nameKey) {
			vm.Name = strings.TrimSpace(strings.TrimPrefix(line, nameKey))
			continue
		}
		// Only network interface lines (net0, net1, ...) carry MACs.
		if !strings.HasPrefix(line, "net") {
			continue
		}
		if mac := macRe.FindString(line); mac != "" {
			mac = strings.ToLower(mac)
			if _, dup := seen[mac]; !dup {
				seen[mac] = struct{}{}
				vm.MACs = append(vm.MACs, mac)
			}
		}
	}
	return vm
}
