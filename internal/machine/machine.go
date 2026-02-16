package machine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bougou/go-ipmi"
)

// HostInfo contains comprehensive system information
type HostInfo struct {
	MachineID   string
	Hostname    string
	OS          string
	Arch        string
	Kernel      string
	Distro      string
	CPUCount    int
	CPUModel    string
	MemoryTotal uint64
	Disks       []DiskInfo
	Interfaces  []InterfaceInfo
	PrimaryIP   string
	IsVM        bool
	IsContainer bool
	VMType      string // "kvm", "vmware", "hyperv", "virtualbox", "wsl2", "docker", "lxc", etc.
	Board       BoardInfo
	Memory      MemoryInfo
	IPMI        IPMIInfo
}

// IPMIInfo contains IPMI/BMC management interface details (bare-metal only)
type IPMIInfo struct {
	IP      string `json:"ip,omitempty"`
	MAC     string `json:"mac,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	Subnet  string `json:"subnet,omitempty"`
}

// MemoryInfo contains RAM module details from DMI tables (bare-metal only)
type MemoryInfo struct {
	Type  string `json:"type,omitempty"`  // e.g., "DDR4", "DDR5"
	Speed uint   `json:"speed,omitempty"` // data rate in MT/s
	Size  uint   `json:"size,omitempty"`  // total size in MB
}

// BoardInfo contains motherboard/BIOS information from DMI (bare-metal only)
type BoardInfo struct {
	Name    string `json:"name,omitempty"`
	Vendor  string `json:"vendor,omitempty"`
	Version string `json:"version,omitempty"`
	Serial  string `json:"serial,omitempty"`

	BIOSVendor  string `json:"bios_vendor,omitempty"`
	BIOSVersion string `json:"bios_version,omitempty"`
	BIOSDate    string `json:"bios_date,omitempty"`

	SysVendor   string `json:"sys_vendor,omitempty"`
	ProductName string `json:"product_name,omitempty"`
	ChassisType string `json:"chassis_type,omitempty"`
}

// DiskInfo contains information about a block device
type DiskInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`  // "SSD" or "HDD"
	Model string `json:"model"`
	Size  uint64 `json:"size"` // bytes
}

// InterfaceInfo contains information about a network interface
type InterfaceInfo struct {
	Name       string   `json:"name"`
	MACAddress string   `json:"mac_address"`
	IPs        []string `json:"ips"`
	CIDRs      []string `json:"cidrs,omitempty"` // e.g., ["172.30.39.167/20"]
}

// GetClientID returns a unique client ID based on machine identification
func GetClientID() string {
	if machineID, err := os.ReadFile("/etc/machine-id"); err == nil {
		id := strings.TrimSpace(string(machineID))
		if id != "" {
			if len(id) > 12 {
				return id[:12]
			}
			return id
		}
	}

	if machineID, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		id := strings.TrimSpace(string(machineID))
		if id != "" {
			if len(id) > 12 {
				return id[:12]
			}
			return id
		}
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}

	data := fmt.Sprintf("%s-%s-%s", hostname, username, runtime.GOOS)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:12]
}

// GetHostname returns the system hostname
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// GetMetadata returns system metadata for registration
func GetMetadata() map[string]string {
	metadata := make(map[string]string)

	metadata["os"] = runtime.GOOS
	metadata["arch"] = runtime.GOARCH
	metadata["goversion"] = runtime.Version()

	if hostname, err := os.Hostname(); err == nil {
		metadata["hostname"] = hostname
	}

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			version := strings.TrimSpace(string(data))
			parts := strings.Fields(version)
			if len(parts) >= 3 {
				metadata["kernel"] = parts[2]
			}
		}

		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					name := strings.TrimPrefix(line, "PRETTY_NAME=")
					name = strings.Trim(name, "\"")
					metadata["distro"] = name
					break
				}
			}
		}
	}

	return metadata
}

// GetLocalIPAddresses returns non-loopback, non-link-local IP addresses
func GetLocalIPAddresses() []string {
	var ips []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil {
				continue
			}
			if ip.IsLoopback() {
				continue
			}
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			ipStr := ip.String()
			if ipStr != "" {
				ips = append(ips, ipStr)
			}
		}
	}

	return ips
}

// CollectHostInfo gathers comprehensive host information
func CollectHostInfo() *HostInfo {
	info := &HostInfo{
		MachineID: getMachineID(),
		Hostname:  GetHostname(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CPUCount:  runtime.NumCPU(),
	}

	if runtime.GOOS == "linux" {
		info.Kernel = getKernelVersion()
		info.Distro = getDistro()
		info.CPUModel = getCPUModel()
		info.MemoryTotal = getMemoryTotal()
		info.Disks = getDisks()
		info.Board = getBoardInfo()
		info.IsVM, info.IsContainer, info.VMType = detectVirtualization(&info.Board)
		if !info.IsVM && !info.IsContainer {
			info.Memory = getMemoryInfo()
			info.IPMI = getIPMIInfo()
		}
	}

	info.Interfaces = getInterfaces()
	info.PrimaryIP = getPrimaryIP(info.Interfaces)

	return info
}

func getMachineID() string {
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}
	if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}
	return ""
}

func getKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	parts := strings.Fields(strings.TrimSpace(string(data)))
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func getDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			name := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(name, "\"")
		}
	}
	return ""
}

// getCPUModel parses /proc/cpuinfo for the first "model name"
func getCPUModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// getMemoryTotal parses /proc/meminfo for MemTotal (kB → bytes)
func getMemoryTotal() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return kb * 1024 // kB to bytes
				}
			}
		}
	}
	return 0
}

// getMemoryInfo reads DMI tables to determine RAM type, speed, and total module size.
// Inspired by github.com/zcalusic/sysinfo memory.go.
// Only meaningful on bare-metal or VMs with DMI passthrough.
func getMemoryInfo() MemoryInfo {
	dmi, err := os.ReadFile("/sys/firmware/dmi/tables/DMI")
	if err != nil {
		return MemoryInfo{}
	}

	var mem MemoryInfo
	var memSizeAlt uint

	for p := 0; p < len(dmi)-1; {
		recType := dmi[p]
		recLen := int(dmi[p+1])

		if recLen < 4 || p+recLen > len(dmi) {
			break
		}

		switch recType {
		case 17: // Memory Device
			if recLen < 0x15 {
				break
			}
			size := uint(binary.LittleEndian.Uint16(dmi[p+0x0c : p+0x0e]))
			if size == 0 || size == 0xffff || size&0x8000 == 0x8000 {
				break
			}
			if size == 0x7fff {
				if recLen >= 0x20 {
					size = uint(binary.LittleEndian.Uint32(dmi[p+0x1c : p+0x20]))
				} else {
					break
				}
			}
			mem.Size += size

			if mem.Type == "" && recLen >= 0x13 {
				// SMBIOS Reference Specification Version 3.8.0, page 103
				memTypes := [...]string{
					"Other", "Unknown", "DRAM", "EDRAM", "VRAM", "SRAM", "RAM", "ROM", "FLASH",
					"EEPROM", "FEPROM", "EPROM", "CDRAM", "3DRAM", "SDRAM", "SGRAM", "RDRAM",
					"DDR", "DDR2", "DDR2 FB-DIMM", "Reserved", "Reserved", "Reserved", "DDR3",
					"FBD2", "DDR4", "LPDDR", "LPDDR2", "LPDDR3", "LPDDR4", "Logical non-volatile device",
					"HBM", "HBM2", "DDR5", "LPDDR5", "HBM3",
				}
				if index := int(dmi[p+0x12]); index >= 1 && index <= len(memTypes) {
					mem.Type = memTypes[index-1]
				}
			}

			if mem.Speed == 0 && recLen >= 0x17 {
				if speed := uint(binary.LittleEndian.Uint16(dmi[p+0x15 : p+0x17])); speed != 0 {
					mem.Speed = speed
				}
			}

		case 19: // Memory Array Mapped Address
			if recLen < 0x0f {
				break
			}
			start := uint(binary.LittleEndian.Uint32(dmi[p+0x04 : p+0x08]))
			end := uint(binary.LittleEndian.Uint32(dmi[p+0x08 : p+0x0c]))
			if start == 0xffffffff && end == 0xffffffff {
				if recLen >= 0x1f {
					start64 := binary.LittleEndian.Uint64(dmi[p+0x0f : p+0x17])
					end64 := binary.LittleEndian.Uint64(dmi[p+0x17 : p+0x1f])
					memSizeAlt += uint((end64 - start64 + 1) / 1048576)
				}
			} else {
				memSizeAlt += (end - start + 1) / 1024
			}

		case 127: // End of Table
			goto done
		}

		// Skip to end of record (past string table)
		p += recLen
		for p < len(dmi)-1 {
			if bytes.Equal(dmi[p:p+2], []byte{0, 0}) {
				p += 2
				break
			}
			p++
		}
	}

done:
	// Fallback: type 19 data supplements type 17 when the latter lacks size info
	if mem.Size == 0 && memSizeAlt > 0 {
		mem.Type = "DRAM"
		mem.Size = memSizeAlt
	}

	return mem
}

// getIPMIInfo reads IPMI/BMC LAN configuration via the local IPMI device.
// Returns empty IPMIInfo if IPMI is not available (VM, no device, no permission).
func getIPMIInfo() IPMIInfo {
	client, err := ipmi.NewOpenClient()
	if err != nil {
		return IPMIInfo{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return IPMIInfo{}
	}
	defer client.Close(ctx)

	lanConfig, err := client.GetLanConfig(ctx, 1)
	if err != nil {
		return IPMIInfo{}
	}

	return IPMIInfo{
		IP:      lanConfig.IP.String(),
		MAC:     lanConfig.MAC.String(),
		Gateway: lanConfig.DefaultGatewayIP.String(),
		Subnet:  lanConfig.SubnetMask.String(),
	}
}

// getDisks scans /sys/block/ for block devices, skipping loop/ram/dm- devices
func getDisks() []DiskInfo {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil
	}

	var disks []DiskInfo
	for _, entry := range entries {
		name := entry.Name()

		// Skip virtual devices
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") {
			continue
		}

		disk := DiskInfo{Name: name}

		// Read size (in 512-byte sectors)
		if data, err := os.ReadFile(fmt.Sprintf("/sys/block/%s/size", name)); err == nil {
			sectors, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			if err == nil {
				disk.Size = sectors * 512
			}
		}

		// Skip disks with zero size
		if disk.Size == 0 {
			continue
		}

		// Read rotational flag (0=SSD, 1=HDD)
		if data, err := os.ReadFile(fmt.Sprintf("/sys/block/%s/queue/rotational", name)); err == nil {
			if strings.TrimSpace(string(data)) == "0" {
				disk.Type = "SSD"
			} else {
				disk.Type = "HDD"
			}
		}

		// Read device model
		if data, err := os.ReadFile(fmt.Sprintf("/sys/block/%s/device/model", name)); err == nil {
			disk.Model = strings.TrimSpace(string(data))
		}

		disks = append(disks, disk)
	}

	return disks
}

// getInterfaces collects network interface info including MACs
func getInterfaces() []InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		info := InterfaceInfo{
			Name:       iface.Name,
			MACAddress: iface.HardwareAddr.String(),
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP != nil && !v.IP.IsLoopback() && !v.IP.IsLinkLocalUnicast() {
						info.IPs = append(info.IPs, v.IP.String())
						info.CIDRs = append(info.CIDRs, v.String()) // e.g., "172.30.39.167/20"
					}
				case *net.IPAddr:
					if v.IP != nil && !v.IP.IsLoopback() && !v.IP.IsLinkLocalUnicast() {
						info.IPs = append(info.IPs, v.IP.String())
					}
				}
			}
		}

		result = append(result, info)
	}

	return result
}

// IsVirtualInterface returns true if the interface name matches known virtual/internal interfaces
func IsVirtualInterface(name string) bool {
	// Exact matches
	switch name {
	case "lo", "docker0":
		return true
	}
	// Prefix matches
	prefixes := []string{"br-", "veth", "virbr", "cni", "flannel", "calico", "weave"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// slurpFile reads a file and returns its trimmed content, or empty string on error.
func slurpFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// getBoardInfo reads motherboard, BIOS, and chassis info from DMI sysfs.
// Inspired by github.com/zcalusic/sysinfo.
func getBoardInfo() BoardInfo {
	return BoardInfo{
		Name:    slurpFile("/sys/class/dmi/id/board_name"),
		Vendor:  slurpFile("/sys/class/dmi/id/board_vendor"),
		Version: slurpFile("/sys/class/dmi/id/board_version"),
		Serial:  slurpFile("/sys/class/dmi/id/board_serial"),

		BIOSVendor:  slurpFile("/sys/class/dmi/id/bios_vendor"),
		BIOSVersion: slurpFile("/sys/class/dmi/id/bios_version"),
		BIOSDate:    slurpFile("/sys/class/dmi/id/bios_date"),

		SysVendor:   slurpFile("/sys/class/dmi/id/sys_vendor"),
		ProductName: slurpFile("/sys/class/dmi/id/product_name"),
		ChassisType: slurpFile("/sys/class/dmi/id/chassis_type"),
	}
}

// detectVirtualization detects if running in a VM or container.
// Board info is used for vendor/product-based detection (already read from DMI).
func detectVirtualization(board *BoardInfo) (isVM bool, isContainer bool, vmType string) {
	isContainer, vmType = detectContainer()
	if isContainer {
		return false, true, vmType
	}
	isVM, vmType = detectVM(board)
	return isVM, false, vmType
}

// detectContainer checks for container environments.
func detectContainer() (bool, string) {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true, "docker"
	}

	// Check cgroup for docker/lxc
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "docker") {
			return true, "docker"
		}
		if strings.Contains(content, "lxc") {
			return true, "lxc"
		}
	}

	return false, ""
}

// detectVM checks for VM environments using multiple signals.
// Inspired by github.com/zcalusic/sysinfo hypervisor detection.
func detectVM(board *BoardInfo) (bool, string) {
	// 1. Check /proc/version for WSL
	if data, err := os.ReadFile("/proc/version"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl") {
			return true, "wsl2"
		}
	}

	// 2. Check /sys/hypervisor/type (catches Xen PV guests without DMI)
	if hvType := slurpFile("/sys/hypervisor/type"); hvType != "" {
		if hvType == "xen" {
			return true, "xenpv"
		}
		return true, hvType
	}

	// 3. Check DMI sys_vendor (board info already collected)
	vendorMap := map[string]string{
		"QEMU":                    "kvm",
		"VMware, Inc.":            "vmware",
		"Microsoft Corporation":   "hyperv",
		"innotek GmbH":            "virtualbox",
		"Xen":                     "xen",
		"Amazon EC2":              "aws",
		"Google":                  "gce",
		"DigitalOcean":            "digitalocean",
		"Parallels Software International Inc.": "parallels",
	}
	if vmType, ok := vendorMap[board.SysVendor]; ok {
		return true, vmType
	}

	// 4. Check DMI product_name
	product := strings.ToLower(board.ProductName)
	switch {
	case strings.Contains(product, "virtualbox"):
		return true, "virtualbox"
	case strings.Contains(product, "vmware"):
		return true, "vmware"
	case strings.Contains(product, "kvm"):
		return true, "kvm"
	case strings.Contains(product, "virtual machine"):
		return true, "hyperv"
	case strings.Contains(product, "hvm domu"):
		return true, "xenhvm"
	}

	// 5. Check BIOS vendor (catches Bochs/QEMU)
	biosVendor := strings.ToLower(board.BIOSVendor)
	switch {
	case strings.Contains(biosVendor, "bochs"):
		return true, "bochs"
	case strings.Contains(biosVendor, "seabios"):
		return true, "kvm"
	}

	return false, ""
}

// getPrimaryIP returns the first non-loopback IPv4 address
func getPrimaryIP(interfaces []InterfaceInfo) string {
	for _, iface := range interfaces {
		for _, ip := range iface.IPs {
			// Prefer IPv4
			parsed := net.ParseIP(ip)
			if parsed != nil && parsed.To4() != nil {
				return ip
			}
		}
	}
	// Fallback to any IP
	for _, iface := range interfaces {
		if len(iface.IPs) > 0 {
			return iface.IPs[0]
		}
	}
	return ""
}
