package ipam

import (
	"context"
	"fmt"
	"net"

	"github.com/go-tangra/go-tangra-client/internal/machine"

	ipampb "github.com/go-tangra/go-tangra-ipam/gen/go/ipam/service/v1"
)

// syncSubnetsAndAddresses ensures subnets and IP address records exist for all host interfaces.
// Errors are logged but not propagated — this is best-effort.
func syncSubnetsAndAddresses(ctx context.Context, clients *IPAMClients, info *machine.HostInfo, deviceID string, tenantID uint32) {
	// Cache subnet CIDRs → subnet ID to avoid repeated RPCs
	subnetCache := make(map[string]string)

	for _, iface := range info.Interfaces {
		if machine.IsVirtualInterface(iface.Name) {
			continue
		}

		for i, cidr := range iface.CIDRs {
			networkCIDR, hostIP, err := computeNetworkCIDR(cidr)
			if err != nil {
				fmt.Printf("  Network: skip invalid CIDR %s: %v\n", cidr, err)
				continue
			}

			// Ensure subnet exists
			subnetID, err := ensureSubnet(ctx, clients.Subnet, tenantID, networkCIDR, subnetCache)
			if err != nil {
				fmt.Printf("  Network: failed to ensure subnet %s: %v\n", networkCIDR, err)
				continue
			}

			// Determine if this IP is the primary
			isPrimary := hostIP == info.PrimaryIP

			// Get the MAC for this interface
			mac := iface.MACAddress

			// Get the IP string for this entry
			var ipStr string
			if i < len(iface.IPs) {
				ipStr = iface.IPs[i]
			} else {
				ipStr = hostIP
			}

			// Ensure IP address record exists
			err = ensureIPAddress(ctx, clients.IpAddress, tenantID, ipStr, subnetID, deviceID, info.Hostname, mac, iface.Name, isPrimary)
			if err != nil {
				fmt.Printf("  Network: failed to ensure IP %s: %v\n", ipStr, err)
			}
		}
	}
}

// computeNetworkCIDR takes "172.30.39.167/20" and returns network CIDR "172.30.32.0/20" and host IP "172.30.39.167"
func computeNetworkCIDR(cidr string) (networkCIDR string, hostIP string, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	ones, _ := ipNet.Mask.Size()
	return fmt.Sprintf("%s/%d", ipNet.IP.String(), ones), ip.String(), nil
}

// ensureSubnet checks if a subnet exists for the given CIDR and creates it if not.
func ensureSubnet(ctx context.Context, client ipampb.SubnetServiceClient, tenantID uint32, networkCIDR string, cache map[string]string) (string, error) {
	// Check cache first
	if id, ok := cache[networkCIDR]; ok {
		return id, nil
	}

	// List all subnets for this tenant and find by CIDR
	subnetID, err := findSubnetByCIDR(ctx, client, tenantID, networkCIDR)
	if err != nil {
		return "", err
	}
	if subnetID != "" {
		cache[networkCIDR] = subnetID
		return subnetID, nil
	}

	// Subnet not found — create it
	name := fmt.Sprintf("auto-%s", networkCIDR)
	status := ipampb.SubnetStatus_SUBNET_STATUS_ACTIVE
	resp, err := client.CreateSubnet(ctx, &ipampb.CreateSubnetRequest{
		TenantId: &tenantID,
		Name:     &name,
		Cidr:     &networkCIDR,
		Status:   &status,
	})
	if err != nil {
		// Handle race condition: subnet may have been created by another client
		subnetID, findErr := findSubnetByCIDR(ctx, client, tenantID, networkCIDR)
		if findErr == nil && subnetID != "" {
			cache[networkCIDR] = subnetID
			return subnetID, nil
		}
		return "", fmt.Errorf("create subnet: %w", err)
	}

	if resp.Subnet != nil && resp.Subnet.Id != nil {
		cache[networkCIDR] = *resp.Subnet.Id
		return *resp.Subnet.Id, nil
	}
	return "", fmt.Errorf("create subnet returned no ID")
}

// findSubnetByCIDR lists subnets and finds one matching the given CIDR.
func findSubnetByCIDR(ctx context.Context, client ipampb.SubnetServiceClient, tenantID uint32, networkCIDR string) (string, error) {
	noPaging := true
	resp, err := client.ListSubnets(ctx, &ipampb.ListSubnetsRequest{
		TenantId: &tenantID,
		NoPaging: &noPaging,
	})
	if err != nil {
		return "", fmt.Errorf("list subnets: %w", err)
	}

	for _, s := range resp.Items {
		if s.Cidr != nil && *s.Cidr == networkCIDR {
			if s.Id != nil {
				return *s.Id, nil
			}
		}
	}
	return "", nil
}

// ensureIPAddress ensures an IP address record exists in IPAM, linked to the device.
func ensureIPAddress(ctx context.Context, client ipampb.IpAddressServiceClient, tenantID uint32, address, subnetID, deviceID, hostname, mac, ifaceName string, isPrimary bool) error {
	// Try to find existing address
	resp, err := client.FindAddress(ctx, &ipampb.FindAddressRequest{
		TenantId: &tenantID,
		Address:  address,
	})
	if err != nil {
		return fmt.Errorf("find address %s: %w", address, err)
	}

	status := ipampb.IpAddressStatus_IP_ADDRESS_STATUS_ACTIVE
	addrType := ipampb.IpAddressType_IP_ADDRESS_TYPE_HOST

	if resp.IpAddress == nil {
		// Address doesn't exist — create it
		_, err := client.CreateIpAddress(ctx, &ipampb.CreateIpAddressRequest{
			TenantId:      &tenantID,
			Address:       &address,
			SubnetId:      &subnetID,
			Hostname:      strPtr(hostname),
			MacAddress:    strPtr(mac),
			DeviceId:      &deviceID,
			InterfaceName: strPtr(ifaceName),
			Status:        &status,
			AddressType:   &addrType,
			IsPrimary:     &isPrimary,
		})
		if err != nil {
			return fmt.Errorf("create address %s: %w", address, err)
		}
		fmt.Printf("  Network: created IP %s in subnet %s\n", address, subnetID)
		return nil
	}

	// Address exists — check if it needs to be updated
	existing := resp.IpAddress
	if existing.DeviceId != nil && *existing.DeviceId == deviceID {
		// Same device, no-op
		return nil
	}

	// Different device or no device — update
	if existing.Id == nil {
		return nil
	}
	_, err = client.UpdateIpAddress(ctx, &ipampb.UpdateIpAddressRequest{
		Id: *existing.Id,
		Data: &ipampb.IpAddress{
			DeviceId:      &deviceID,
			Hostname:      strPtr(hostname),
			MacAddress:    strPtr(mac),
			InterfaceName: strPtr(ifaceName),
			Status:        &status,
			IsPrimary:     &isPrimary,
		},
	})
	if err != nil {
		return fmt.Errorf("update address %s: %w", address, err)
	}
	fmt.Printf("  Network: updated IP %s (linked to device %s)\n", address, deviceID)
	return nil
}
