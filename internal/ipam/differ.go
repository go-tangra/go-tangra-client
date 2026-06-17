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
	if last.RebootRequired != current.RebootRequired {
		return true
	}
	if last.UnattendedUpgrades != current.UnattendedUpgrades {
		return true
	}

	// Compare MAC addresses (sorted)
	if changedList(last.MACAddresses, current.MACAddresses) {
		return true
	}

	// Compare hosted-guest fingerprint so guest add/remove/MAC-change re-syncs
	if changedList(last.HostedVMs, current.HostedVMs) {
		return true
	}

	return false
}

// changedList reports whether two string slices differ, ignoring order.
func changedList(a, b []string) bool {
	as := sortedCopy(a)
	bs := sortedCopy(b)
	if len(as) != len(bs) {
		return true
	}
	for i := range as {
		if as[i] != bs[i] {
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

	var hostedVMs []string
	for _, vm := range info.HostedVMs {
		for _, mac := range vm.MACs {
			hostedVMs = append(hostedVMs, vm.VMID+":"+mac)
		}
	}

	return &storage.HostInfoSnapshot{
		Hostname:           info.Hostname,
		OS:                 info.OS,
		Distro:             info.Distro,
		Kernel:             info.Kernel,
		CPUModel:           info.CPUModel,
		PrimaryIP:          info.PrimaryIP,
		CPUCount:           info.CPUCount,
		DiskCount:          len(info.Disks),
		MemoryTotal:        info.MemoryTotal,
		MACAddresses:       macs,
		IsVM:               info.IsVM,
		IsContainer:        info.IsContainer,
		IPMIIP:             info.IPMI.IP,
		HostedVMs:          hostedVMs,
		RebootRequired:     info.RebootRequired,
		UnattendedUpgrades: info.UnattendedUpgrades,
	}
}

func sortedCopy(s []string) []string {
	c := make([]string, len(s))
	copy(c, s)
	sort.Strings(c)
	return c
}
