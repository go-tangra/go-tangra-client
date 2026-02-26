package ipam

import (
	"context"
	"fmt"

	"github.com/go-tangra/go-tangra-client/internal/packages"

	ipampb "github.com/go-tangra/go-tangra-ipam/gen/go/ipam/service/v1"
)

// SyncPackages collects installed packages and syncs them to IPAM
func SyncPackages(ctx context.Context, client ipampb.DevicePackageServiceClient, deviceID string) error {
	mgr := packages.New()

	pkgs, packageManager, err := mgr.GetPackages()
	if err != nil {
		return fmt.Errorf("failed to collect packages: %w", err)
	}

	if len(pkgs) == 0 {
		fmt.Println("  packages: no packages detected")
		return nil
	}

	// Convert to proto
	protoPkgs := make([]*ipampb.DevicePackage, len(pkgs))
	for i, pkg := range pkgs {
		protoPkgs[i] = &ipampb.DevicePackage{
			Name:             ptrStr(pkg.Name),
			CurrentVersion:   ptrStr(pkg.CurrentVersion),
			AvailableVersion: ptrStr(pkg.AvailableVersion),
			NeedsUpdate:      &pkg.NeedsUpdate,
			IsSecurityUpdate: &pkg.IsSecurityUpdate,
			Description:      ptrStr(pkg.Description),
		}
	}

	resp, err := client.SyncDevicePackages(ctx, &ipampb.SyncDevicePackagesRequest{
		DeviceId:       deviceID,
		Packages:       protoPkgs,
		PackageManager: &packageManager,
	})
	if err != nil {
		return fmt.Errorf("failed to sync packages: %w", err)
	}

	fmt.Printf("  packages: synced %d packages (%d updates, %d security)\n",
		resp.GetTotal(), resp.GetUpdatesAvailable(), resp.GetSecurityUpdates())

	return nil
}

// syncPackagesBestEffort calls SyncPackages, logging errors but not propagating them
func syncPackagesBestEffort(ctx context.Context, clients *IPAMClients, deviceID string) {
	if clients.DevicePackage == nil {
		return
	}
	fmt.Println("  Syncing packages...")
	if err := SyncPackages(ctx, clients.DevicePackage, deviceID); err != nil {
		fmt.Printf("  packages: sync failed (best-effort): %v\n", err)
	}
}

func ptrStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
