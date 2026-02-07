package lcm

import (
	"context"
	"fmt"
	"time"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"

	"github.com/go-tangra/go-tangra-client/internal/hook"
	"github.com/go-tangra/go-tangra-client/internal/storage"
)

// SyncCertificates fetches and stores all certificates for the client
func SyncCertificates(ctx context.Context, grpcClient lcmV1.LcmClientServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig, clientID string) (int, error) {
	resp, err := grpcClient.ListClientCertificates(ctx, &lcmV1.ListClientCertificatesRequest{
		ClientId:              &clientID,
		IncludeCertificatePem: boolPtr(true),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list certificates: %w", err)
	}

	caCertPEM := resp.GetCaCertificatePem()
	updatedCount := 0

	for _, certInfo := range resp.GetCertificates() {
		if certInfo.GetStatus() != lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED {
			continue
		}

		certName := getCertName(certInfo)
		certPEM := certInfo.GetCertificatePem()

		if certPEM == "" {
			fmt.Printf("  Skipping %s: no certificate PEM\n", certName)
			continue
		}

		// Check if certificate has changed
		existingMeta, _ := store.LoadMetadata(certName)
		if existingMeta != nil && existingMeta.SerialNumber == certInfo.GetSerialNumber() {
			fmt.Printf("  %s: up to date\n", certName)
			continue
		}

		isRenewal := existingMeta != nil
		previousSerial := ""
		renewalCount := 0
		if isRenewal {
			previousSerial = existingMeta.SerialNumber
			renewalCount = existingMeta.RenewalCount + 1
		}

		// Load existing private key
		keyPEM := ""
		if store.CertificateExists(certName) {
			keyPEM, _ = store.LoadPrivateKey(certName)
		}

		// Build metadata
		var expiresAt time.Time
		if certInfo.GetExpiresAt() != nil {
			expiresAt = certInfo.GetExpiresAt().AsTime()
		}
		var issuedAt time.Time
		if certInfo.GetIssuedAt() != nil {
			issuedAt = certInfo.GetIssuedAt().AsTime()
		}

		metadata := &storage.CertMetadata{
			Name:           certName,
			CommonName:     certInfo.GetCommonName(),
			SerialNumber:   certInfo.GetSerialNumber(),
			Fingerprint:    certInfo.GetFingerprintSha256(),
			IssuedAt:       issuedAt,
			ExpiresAt:      expiresAt,
			IssuerName:     certInfo.GetIssuerName(),
			DNSNames:       certInfo.GetDnsNames(),
			IPAddresses:    certInfo.GetIpAddresses(),
			PreviousSerial: previousSerial,
			RenewalCount:   renewalCount,
		}

		// Save certificate
		if err := store.SaveCertificate(certName, certPEM, keyPEM, caCertPEM, metadata); err != nil {
			fmt.Printf("  %s: failed to save: %v\n", certName, err)
			continue
		}

		action := "downloaded"
		if isRenewal {
			action = "renewed"
		}
		fmt.Printf("  %s: %s (serial: %s)\n", certName, action, certInfo.GetSerialNumber())
		updatedCount++

		// Run deploy hook
		runDeployHookForCert(ctx, hookRunner, hookConfig, store, certInfo, certName, isRenewal, expiresAt)
	}

	return updatedCount, nil
}

func runDeployHookForCert(ctx context.Context, hookRunner *hook.Runner, hookConfig *hook.HookConfig, store *storage.CertStore, certInfo *lcmV1.CertificateInfo, certName string, isRenewal bool, expiresAt time.Time) {
	if hookConfig == nil || (hookConfig.BashScript == "" && hookConfig.ScriptFile == "") {
		return
	}

	paths := store.GetPaths(certName)
	hookCtx := &hook.HookContext{
		CertName:      certName,
		CertPath:      paths.CertFile,
		KeyPath:       paths.PrivKeyFile,
		ChainPath:     paths.ChainFile,
		FullChainPath: paths.FullChainFile,
		CommonName:    certInfo.GetCommonName(),
		DNSNames:      certInfo.GetDnsNames(),
		IPAddresses:   certInfo.GetIpAddresses(),
		SerialNumber:  certInfo.GetSerialNumber(),
		ExpiresAt:     expiresAt.Format(time.RFC3339),
		IsRenewal:     isRenewal,
	}

	fmt.Printf("    Running deploy hook...\n")
	result := hookRunner.RunDeployHook(ctx, hookConfig, hookCtx)
	if result.Success {
		fmt.Printf("    Hook completed successfully (%.2fs)\n", result.Duration.Seconds())
		_ = store.UpdateMetadata(certName, func(m *storage.CertMetadata) {
			m.LastHookExecution = time.Now()
		})
	} else {
		fmt.Printf("    Hook failed (exit %d): %s\n", result.ExitCode, result.ErrorMsg)
	}
	if result.Output != "" {
		fmt.Printf("    Output: %s\n", result.Output)
	}
}

func getCertName(certInfo *lcmV1.CertificateInfo) string {
	if certInfo.GetName() != "" {
		return certInfo.GetName()
	}
	if certInfo.GetCommonName() != "" {
		return certInfo.GetCommonName()
	}
	return "unknown"
}

func boolPtr(v bool) *bool {
	return &v
}
