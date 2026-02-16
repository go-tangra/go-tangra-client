package ipam

import (
	"encoding/json"
	"fmt"

	"github.com/go-tangra/go-tangra-client/internal/machine"

	ipampb "github.com/go-tangra/go-tangra-ipam/gen/go/ipam/service/v1"
)

// DeviceMetadata is the JSON structure stored in the IPAM device metadata field
type DeviceMetadata struct {
	MachineID   string                  `json:"machine_id"`
	Arch        string                  `json:"arch"`
	Kernel      string                  `json:"kernel"`
	CPUModel    string                  `json:"cpu_model"`
	CPUCount    int                     `json:"cpu_count"`
	MemoryTotal uint64                  `json:"memory_total"`
	VMType      string                  `json:"vm_type,omitempty"`
	Board       *machine.BoardInfo      `json:"board,omitempty"`
	Memory      *machine.MemoryInfo     `json:"memory,omitempty"`
	Disks       []machine.DiskInfo      `json:"disks,omitempty"`
	Interfaces  []machine.InterfaceInfo `json:"interfaces,omitempty"`
	IPMI        *machine.IPMIInfo      `json:"ipmi,omitempty"`
}

// resolveDeviceType determines the IPAM device type based on host info
func resolveDeviceType(info *machine.HostInfo) ipampb.DeviceType {
	if info.IsContainer {
		return ipampb.DeviceType_DEVICE_TYPE_CONTAINER
	}
	if info.IsVM {
		return ipampb.DeviceType_DEVICE_TYPE_VM
	}
	return ipampb.DeviceType_DEVICE_TYPE_SERVER
}

// resolveHardwareInfo returns manufacturer, model, serial from board info,
// falling back to VM-type-based values when DMI is unavailable.
func resolveHardwareInfo(info *machine.HostInfo) (manufacturer, model, serial string) {
	manufacturer = info.Board.SysVendor
	if manufacturer == "" {
		manufacturer = info.Board.Vendor
	}
	model = info.Board.ProductName
	if model == "" {
		model = info.Board.Name
	}
	serial = info.Board.Serial

	// Fallback for VMs/containers where DMI sysfs is not available
	if manufacturer == "" && (info.IsVM || info.IsContainer) {
		switch info.VMType {
		case "wsl2":
			manufacturer = "Microsoft"
			model = "WSL2 (Hyper-V)"
		case "hyperv":
			manufacturer = "Microsoft"
			model = "Hyper-V Virtual Machine"
		case "kvm":
			manufacturer = "QEMU/KVM"
			model = "KVM Virtual Machine"
		case "vmware":
			manufacturer = "VMware, Inc."
			model = "VMware Virtual Machine"
		case "virtualbox":
			manufacturer = "Oracle"
			model = "VirtualBox Virtual Machine"
		case "xen":
			manufacturer = "Xen"
			model = "Xen Virtual Machine"
		case "parallels":
			manufacturer = "Parallels"
			model = "Parallels Virtual Machine"
		case "docker":
			manufacturer = "Docker"
			model = "Docker Container"
		case "lxc":
			manufacturer = "LXC"
			model = "LXC Container"
		}
	}
	return
}

// BuildCreateRequest maps HostInfo to an IPAM CreateDeviceRequest
func BuildCreateRequest(info *machine.HostInfo, tenantID uint32) *ipampb.CreateDeviceRequest {
	deviceType := resolveDeviceType(info)
	status := ipampb.DeviceStatus_DEVICE_STATUS_ACTIVE
	osType := "linux"
	metadataJSON := buildMetadataJSON(info)
	manufacturer, model, serial := resolveHardwareInfo(info)

	req := &ipampb.CreateDeviceRequest{
		TenantId:     &tenantID,
		Name:         &info.Hostname,
		DeviceType:   &deviceType,
		Status:       &status,
		OsType:       &osType,
		OsVersion:    strPtr(info.Distro),
		PrimaryIp:    strPtr(info.PrimaryIP),
		ManagementIp: strPtr(info.IPMI.IP),
		Manufacturer: strPtr(manufacturer),
		Model:        strPtr(model),
		SerialNumber: strPtr(serial),
		Metadata:     strPtr(metadataJSON),
	}

	return req
}

// BuildUpdateRequest maps HostInfo to an IPAM UpdateDeviceRequest
func BuildUpdateRequest(deviceID string, info *machine.HostInfo) *ipampb.UpdateDeviceRequest {
	deviceType := resolveDeviceType(info)
	status := ipampb.DeviceStatus_DEVICE_STATUS_ACTIVE
	osType := "linux"
	metadataJSON := buildMetadataJSON(info)
	manufacturer, model, serial := resolveHardwareInfo(info)

	return &ipampb.UpdateDeviceRequest{
		Id: deviceID,
		Data: &ipampb.Device{
			Name:         &info.Hostname,
			DeviceType:   &deviceType,
			Status:       &status,
			OsType:       &osType,
			OsVersion:    strPtr(info.Distro),
			PrimaryIp:    strPtr(info.PrimaryIP),
			ManagementIp: strPtr(info.IPMI.IP),
			Manufacturer: strPtr(manufacturer),
			Model:        strPtr(model),
			SerialNumber: strPtr(serial),
			Metadata:     strPtr(metadataJSON),
		},
	}
}

func buildMetadataJSON(info *machine.HostInfo) string {
	var board *machine.BoardInfo
	if info.Board.Vendor != "" || info.Board.Name != "" || info.Board.SysVendor != "" {
		board = &info.Board
	}

	var memory *machine.MemoryInfo
	if info.Memory.Type != "" || info.Memory.Speed != 0 {
		memory = &info.Memory
	}

	var ipmiInfo *machine.IPMIInfo
	if info.IPMI.IP != "" {
		ipmiInfo = &info.IPMI
	}

	meta := DeviceMetadata{
		MachineID:   info.MachineID,
		Arch:        info.Arch,
		Kernel:      info.Kernel,
		CPUModel:    info.CPUModel,
		CPUCount:    info.CPUCount,
		MemoryTotal: info.MemoryTotal,
		VMType:      info.VMType,
		Board:       board,
		Memory:      memory,
		IPMI:        ipmiInfo,
		Disks:       info.Disks,
		Interfaces:  info.Interfaces,
	}

	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Sprintf(`{"error":"%s"}`, err.Error())
	}
	return string(data)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
