package ipam

import (
	"context"
	"fmt"
	"time"

	"github.com/go-tangra/go-tangra-client/internal/machine"
	"github.com/go-tangra/go-tangra-client/internal/storage"
	"github.com/go-tangra/go-tangra-client/pkg/backoff"

	ipampb "github.com/go-tangra/go-tangra-ipam/gen/go/ipam/service/v1"
)

// IPAMClients holds gRPC clients for all IPAM services used by the sync logic
type IPAMClients struct {
	Device        ipampb.DeviceServiceClient
	Subnet        ipampb.SubnetServiceClient
	IpAddress     ipampb.IpAddressServiceClient
	DevicePackage ipampb.DevicePackageServiceClient
}

// SyncDevice performs a single device sync: collect -> diff -> create/update -> save state
func SyncDevice(ctx context.Context, clients *IPAMClients, stateStore *storage.StateStore, tenantID uint32, clientID string) (bool, error) {
	// Collect current host info
	info := machine.CollectHostInfo()
	currentSnapshot := SnapshotFromHostInfo(info)

	// Load last synced state
	state, err := stateStore.Load()
	if err != nil {
		return false, fmt.Errorf("failed to load state: %w", err)
	}

	// Create new device if no state exists
	if state == nil || state.DeviceID == "" {
		fmt.Println("  No existing device found, creating new device...")
		req := BuildCreateRequest(info, tenantID)
		resp, err := clients.Device.CreateDevice(ctx, req)
		if err != nil {
			return false, fmt.Errorf("failed to create device: %w", err)
		}

		deviceID := ""
		if resp.Device != nil && resp.Device.Id != nil {
			deviceID = *resp.Device.Id
		}

		newState := &storage.DeviceState{
			DeviceID:     deviceID,
			TenantID:     tenantID,
			LastSyncTime: time.Now(),
			LastHostInfo: currentSnapshot,
		}
		if err := stateStore.Save(newState); err != nil {
			return false, fmt.Errorf("failed to save state: %w", err)
		}

		fmt.Printf("  Device created: %s\n", deviceID)

		// Sync subnets and IPs (best-effort)
		syncSubnetsAndAddresses(ctx, clients, info, deviceID, tenantID)

		// Sync packages (best-effort)
		syncPackagesBestEffort(ctx, clients, deviceID)

		return true, nil
	}

	// Check for hardware/network changes
	changed := HasChanges(state.LastHostInfo, currentSnapshot)

	if changed {
		// Update existing device
		fmt.Printf("  Changes detected, updating device %s...\n", state.DeviceID)
		req := BuildUpdateRequest(state.DeviceID, info)
		_, err = clients.Device.UpdateDevice(ctx, req)
		if err != nil {
			return false, fmt.Errorf("failed to update device: %w", err)
		}

		// Save updated state
		state.LastSyncTime = time.Now()
		state.LastHostInfo = currentSnapshot
		if err := stateStore.Save(state); err != nil {
			return false, fmt.Errorf("failed to save state: %w", err)
		}

		fmt.Printf("  Device updated: %s\n", state.DeviceID)

		// Sync subnets and IPs (best-effort)
		syncSubnetsAndAddresses(ctx, clients, info, state.DeviceID, tenantID)
	} else {
		fmt.Println("  No hardware changes detected")
	}

	// Always sync packages regardless of hardware changes
	syncPackagesBestEffort(ctx, clients, state.DeviceID)

	return changed, nil
}

// RunSyncLoop runs the IPAM sync loop at the given interval
func RunSyncLoop(ctx context.Context, clients *IPAMClients, stateStore *storage.StateStore, tenantID uint32, clientID string, interval time.Duration) error {
	bo := backoff.New()

	// Initial sync
	fmt.Println("IPAM: Running initial sync...")
	changed, err := SyncDevice(ctx, clients, stateStore, tenantID, clientID)
	if err != nil {
		fmt.Printf("IPAM: Initial sync failed: %v\n", err)
		// Backoff before first tick
		fmt.Print("IPAM: ")
		if _, cancelled := bo.Wait(ctx); cancelled {
			return nil
		}
	} else {
		bo.Reset()
		if changed {
			fmt.Println("IPAM: Initial sync completed with changes")
		} else {
			fmt.Println("IPAM: Initial sync completed, no changes")
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("IPAM: Sync loop stopped")
			return nil
		case <-ticker.C:
			fmt.Println("IPAM: Running periodic sync...")
			changed, err := SyncDevice(ctx, clients, stateStore, tenantID, clientID)
			if err != nil {
				fmt.Printf("IPAM: Sync failed: %v\n", err)
				// On repeated failures, use backoff for next retry
				fmt.Print("IPAM: ")
				if _, cancelled := bo.Wait(ctx); cancelled {
					return nil
				}
			} else {
				bo.Reset()
				if changed {
					fmt.Println("IPAM: Sync completed with changes")
				}
			}
		}
	}
}
