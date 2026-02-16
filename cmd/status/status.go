package status

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/machine"
	"github.com/go-tangra/go-tangra-client/internal/storage"
	"github.com/go-tangra/go-tangra-client/pkg/client"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
)

var requestID string

// Command is the status command
var Command = &cobra.Command{
	Use:   "status",
	Short: "Show certificate and device status",
	Long: `Show the current status of this client, including:
  - Local machine info (hostname, machine-id)
  - IPAM device state (device ID, last sync time)
  - LCM certificate metadata (stored certs)
  - Optionally check a pending registration request status

Example:
  tangra-client status
  tangra-client status --request-id abc123-def456
`,
	RunE: runStatus,
}

func init() {
	Command.Flags().StringVar(&requestID, "request-id", "", "Check status of a pending LCM registration request")
}

func runStatus(c *cobra.Command, args []string) error {
	clientID := cmd.GetClientID()
	configDir := cmd.GetConfigDir()

	fmt.Printf("Tangra Client Status\n")
	fmt.Printf("====================\n\n")

	// Local machine info
	fmt.Printf("Machine Info:\n")
	fmt.Printf("  Client ID:   %s\n", clientID)
	fmt.Printf("  Hostname:    %s\n", machine.GetHostname())
	fmt.Printf("  Machine ID:  %s\n", machine.GetClientID())

	// IPMI info (collected inline for status display)
	hostInfo := machine.CollectHostInfo()
	if hostInfo.IPMI.IP != "" {
		fmt.Printf("  IPMI IP:     %s\n", hostInfo.IPMI.IP)
		if hostInfo.IPMI.MAC != "" {
			fmt.Printf("  IPMI MAC:    %s\n", hostInfo.IPMI.MAC)
		}
	}
	fmt.Println()

	// IPAM device state
	stateStore := storage.NewStateStore(configDir)
	state, err := stateStore.Load()
	if err != nil {
		fmt.Printf("IPAM State: Error loading: %v\n", err)
	} else if state == nil {
		fmt.Printf("IPAM State: Not synced yet\n")
	} else {
		fmt.Printf("IPAM State:\n")
		fmt.Printf("  Device ID:    %s\n", state.DeviceID)
		fmt.Printf("  Tenant ID:    %d\n", state.TenantID)
		fmt.Printf("  Last Sync:    %s\n", state.LastSyncTime.Format(time.RFC3339))
		if state.LastHostInfo != nil {
			fmt.Printf("  Last Hostname: %s\n", state.LastHostInfo.Hostname)
			fmt.Printf("  Last IP:       %s\n", state.LastHostInfo.PrimaryIP)
		}
	}
	fmt.Println()

	// LCM certificate info
	certStore, err := storage.NewCertStore(configDir)
	if err != nil {
		fmt.Printf("LCM Certificates: Error initializing store: %v\n", err)
	} else {
		allMeta, err := certStore.GetAllMetadata()
		if err != nil {
			fmt.Printf("LCM Certificates: Error loading: %v\n", err)
		} else if len(allMeta) == 0 {
			fmt.Printf("LCM Certificates: None stored\n")
		} else {
			fmt.Printf("LCM Certificates: %d stored\n", len(allMeta))
			for _, meta := range allMeta {
				fmt.Printf("  - %s\n", meta.Name)
				fmt.Printf("    Common Name:   %s\n", meta.CommonName)
				fmt.Printf("    Serial:        %s\n", meta.SerialNumber)
				fmt.Printf("    Issued:        %s\n", meta.IssuedAt.Format(time.RFC3339))
				fmt.Printf("    Expires:       %s\n", meta.ExpiresAt.Format(time.RFC3339))
				fmt.Printf("    Last Updated:  %s\n", meta.LastUpdated.Format(time.RFC3339))
				if meta.RenewalCount > 0 {
					fmt.Printf("    Renewals:      %d\n", meta.RenewalCount)
				}
			}
		}
	}
	fmt.Println()

	// Check mTLS cert files
	certFile := cmd.GetCertFile()
	keyFile := cmd.GetKeyFile()
	caFile := cmd.GetCAFile()

	fmt.Printf("mTLS Identity:\n")
	fmt.Printf("  Cert:  %s (exists: %v)\n", certFile, fileExists(certFile))
	fmt.Printf("  Key:   %s (exists: %v)\n", keyFile, fileExists(keyFile))
	fmt.Printf("  CA:    %s (exists: %v)\n", caFile, fileExists(caFile))

	// Optionally check LCM request status
	if requestID != "" {
		fmt.Printf("\n--- LCM Request Status ---\n")
		return checkRequestStatus(clientID)
	}

	return nil
}

func checkRequestStatus(clientID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverAddr := cmd.GetServerAddr()

	conn, err := client.CreateTLSConnectionWithoutClientCert(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to LCM server: %w", err)
	}
	defer conn.Close()

	grpcClient := lcmV1.NewLcmClientServiceClient(conn)

	req := &lcmV1.GetRequestStatusRequest{
		RequestId: requestID,
		ClientId:  clientID,
	}

	resp, err := grpcClient.GetRequestStatus(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get request status: %w", err)
	}

	fmt.Printf("Request ID: %s\n", requestID)
	fmt.Printf("Status:     %s\n", statusToString(resp.GetStatus()))

	if resp.Message != nil && *resp.Message != "" {
		fmt.Printf("Message:    %s\n", *resp.Message)
	}
	if resp.CreateTime != nil {
		fmt.Printf("Created:    %s\n", resp.CreateTime.AsTime().Format(time.RFC3339))
	}
	if resp.UpdateTime != nil {
		fmt.Printf("Updated:    %s\n", resp.UpdateTime.AsTime().Format(time.RFC3339))
	}

	return nil
}

func statusToString(status lcmV1.ClientCertificateStatus) string {
	switch status {
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED:
		return "ISSUED"
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING:
		return "PENDING"
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED:
		return "REVOKED"
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_UNKNOWN:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
