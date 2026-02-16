package ipam

import (
	"sort"

	"github.com/go-tangra/go-tangra-client/internal/machine"
	"github.com/go-tangra/go-tangra-client/internal/storage"
)

// HasChanges compares the last synced snapshot with current host info
func HasChanges(last *storage.HostInfoSnapshot, current *storage.HostInfoSnapshot) bool {
	if last == nil {
		return true
	}

	if last.Hostname != current.Hostname {
		return true
	}
	if last.OS != current.OS {
		return true
	}
	if last.Distro != current.Distro {
		return true
	}
	if last.Kernel != current.Kernel {
		return true
	}
	if last.CPUModel != current.CPUModel {
		return true
	}
	if last.CPUCount != current.CPUCount {
		return true
	}
	if last.MemoryTotal != current.MemoryTotal {
		return true
	}
	if last.PrimaryIP != current.PrimaryIP {
		return true
	}
	if last.DiskCount != current.DiskCount {
		return true
	}
	if last.IsVM != current.IsVM {
		return true
	}
	if last.IsContainer != current.IsContainer {
		return true
	}
	if last.IPMIIP != current.IPMIIP {
		return true
	}

	// Compare MAC addresses (sorted)
	lastMACs := sortedCopy(last.MACAddresses)
	currentMACs := sortedCopy(current.MACAddresses)
	if len(lastMACs) != len(currentMACs) {
		return true
	}
	for i := range lastMACs {
		if lastMACs[i] != currentMACs[i] {
			return true
		}
	}

	return false
}

// SnapshotFromHostInfo creates a HostInfoSnapshot from HostInfo
func SnapshotFromHostInfo(info *machine.HostInfo) *storage.HostInfoSnapshot {
	var macs []string
	for _, iface := range info.Interfaces {
		if iface.MACAddress != "" {
			macs = append(macs, iface.MACAddress)
		}
	}

	return &storage.HostInfoSnapshot{
		Hostname:     info.Hostname,
		OS:           info.OS,
		Distro:       info.Distro,
		Kernel:       info.Kernel,
		CPUModel:     info.CPUModel,
		PrimaryIP:    info.PrimaryIP,
		CPUCount:     info.CPUCount,
		DiskCount:    len(info.Disks),
		MemoryTotal:  info.MemoryTotal,
		MACAddresses: macs,
		IsVM:         info.IsVM,
		IsContainer:  info.IsContainer,
		IPMIIP:       info.IPMI.IP,
	}
}

func sortedCopy(s []string) []string {
	c := make([]string, len(s))
	copy(c, s)
	sort.Strings(c)
	return c
}
