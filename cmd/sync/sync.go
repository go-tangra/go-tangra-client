package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/ipam"
	"github.com/go-tangra/go-tangra-client/internal/machine"
	"github.com/go-tangra/go-tangra-client/internal/storage"
	"github.com/go-tangra/go-tangra-client/pkg/client"

	ipampb "github.com/go-tangra/go-tangra-ipam/gen/go/ipam/service/v1"
)

var (
	force  bool
	dryRun bool
)

// Command is the sync command
var Command = &cobra.Command{
	Use:   "sync",
	Short: "One-shot IPAM device sync",
	Long: `Sync the current host's information with the IPAM server.

This command collects host information (hostname, IPs, CPU, memory, disks, NICs)
and creates or updates the device entry in IPAM.

Example:
  tangra-client sync --tenant-id 1
  tangra-client sync --tenant-id 1 --force
  tangra-client sync --tenant-id 1 --dry-run
`,
	RunE: runSync,
}

func init() {
	Command.Flags().BoolVar(&force, "force", false, "Force sync even if no changes detected")
	Command.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be synced without making changes")
}

func runSync(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientID := cmd.GetClientID()
	tenantID := cmd.GetTenantID()
	ipamServerAddr := cmd.GetIPAMServerAddr()
	configDir := cmd.GetConfigDir()

	fmt.Printf("IPAM Sync\n")
	fmt.Printf("  Client ID:   %s\n", clientID)
	fmt.Printf("  Tenant ID:   %d\n", tenantID)
	fmt.Printf("  IPAM Server: %s\n", ipamServerAddr)
	fmt.Println()

	if dryRun {
		return runDryRun(configDir)
	}

	// Connect to IPAM server
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	caFile := viper.GetString("ca")

	conn, err := client.CreateMTLSConnection(ipamServerAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to IPAM server: %w", err)
	}
	defer conn.Close()

	clients := &ipam.IPAMClients{
		Device:    ipampb.NewDeviceServiceClient(conn),
		Subnet:    ipampb.NewSubnetServiceClient(conn),
		IpAddress: ipampb.NewIpAddressServiceClient(conn),
	}
	stateStore := storage.NewStateStore(configDir)

	if force {
		// Clear last host info to force an update
		state, _ := stateStore.Load()
		if state != nil {
			state.LastHostInfo = nil
			_ = stateStore.Save(state)
		}
	}

	changed, err := ipam.SyncDevice(ctx, clients, stateStore, tenantID, clientID)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	if changed {
		fmt.Println("\nSync completed successfully with changes.")
	} else {
		fmt.Println("\nSync completed, no changes detected.")
	}

	return nil
}

func runDryRun(configDir string) error {
	info := machine.CollectHostInfo()
	stateStore := storage.NewStateStore(configDir)

	state, _ := stateStore.Load()

	fmt.Println("Current host info:")
	fmt.Printf("  Hostname:    %s\n", info.Hostname)
	fmt.Printf("  Machine ID:  %s\n", info.MachineID)
	fmt.Printf("  OS:          %s/%s\n", info.OS, info.Arch)
	fmt.Printf("  Distro:      %s\n", info.Distro)
	fmt.Printf("  Kernel:      %s\n", info.Kernel)
	fmt.Printf("  CPU:         %s (%d cores)\n", info.CPUModel, info.CPUCount)
	fmt.Printf("  Memory:      %d MB\n", info.MemoryTotal/1024/1024)
	fmt.Printf("  Primary IP:  %s\n", info.PrimaryIP)

	// VM/Container detection
	if info.IsContainer {
		fmt.Printf("  Device Type: Container (%s)\n", info.VMType)
	} else if info.IsVM {
		fmt.Printf("  Device Type: Virtual Machine (%s)\n", info.VMType)
	} else {
		fmt.Printf("  Device Type: Server (bare-metal)\n")
	}

	// Memory module info (bare-metal only)
	if info.Memory.Type != "" || info.Memory.Speed != 0 {
		fmt.Printf("  Memory Type: %s @ %d MT/s (%d MB)\n", info.Memory.Type, info.Memory.Speed, info.Memory.Size)
	}

	// Board / hardware info
	b := info.Board
	if b.SysVendor != "" || b.ProductName != "" || b.Vendor != "" {
		fmt.Println("  Board:")
		if b.SysVendor != "" {
			fmt.Printf("    Manufacturer: %s\n", b.SysVendor)
		} else if b.Vendor != "" {
			fmt.Printf("    Vendor:       %s\n", b.Vendor)
		}
		if b.ProductName != "" {
			fmt.Printf("    Product:      %s\n", b.ProductName)
		} else if b.Name != "" {
			fmt.Printf("    Board Name:   %s\n", b.Name)
		}
		if b.Serial != "" {
			fmt.Printf("    Serial:       %s\n", b.Serial)
		}
		if b.BIOSVendor != "" {
			fmt.Printf("    BIOS:         %s %s (%s)\n", b.BIOSVendor, b.BIOSVersion, b.BIOSDate)
		}
		if b.ChassisType != "" {
			fmt.Printf("    Chassis:      %s\n", b.ChassisType)
		}
	}

	fmt.Printf("  Disks:       %d\n", len(info.Disks))
	for _, d := range info.Disks {
		fmt.Printf("    - %s: %s %s (%d GB)\n", d.Name, d.Type, d.Model, d.Size/1024/1024/1024)
	}
	fmt.Printf("  Interfaces:  %d\n", len(info.Interfaces))
	for _, iface := range info.Interfaces {
		virtual := ""
		if machine.IsVirtualInterface(iface.Name) {
			virtual = " [virtual]"
		}
		fmt.Printf("    - %s%s: MAC=%s IPs=%v CIDRs=%v\n", iface.Name, virtual, iface.MACAddress, iface.IPs, iface.CIDRs)
	}

	if state != nil && state.DeviceID != "" {
		snapshot := ipam.SnapshotFromHostInfo(info)
		if ipam.HasChanges(state.LastHostInfo, snapshot) {
			fmt.Println("\nChanges detected - would UPDATE device:", state.DeviceID)
		} else {
			fmt.Println("\nNo changes detected - would skip update")
		}
	} else {
		fmt.Println("\nNo existing device - would CREATE new device")
	}

	return nil
}
