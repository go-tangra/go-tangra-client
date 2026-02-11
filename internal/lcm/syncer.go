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
func SyncCertificates(ctx context.Context, grpcClient lcmV1.LcmClientServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig) (int, error) {
	resp, err := grpcClient.ListClientCertificates(ctx, &lcmV1.ListClientCertificatesRequest{
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

// SyncCertificateJobs fetches completed certificate jobs and downloads any
// certificates (including private keys) that are not yet stored locally.
func SyncCertificateJobs(ctx context.Context, jobClient lcmV1.LcmCertificateJobServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig) (int, error) {
	completedStatus := lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED
	resp, err := jobClient.ListJobs(ctx, &lcmV1.ListJobsRequest{
		Status: &completedStatus,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to list certificate jobs: %w", err)
	}

	updatedCount := 0

	for _, job := range resp.GetJobs() {
		certName := job.GetCommonName()
		if certName == "" {
			continue
		}

		// Check if certificate already exists locally with same serial
		existingMeta, _ := store.LoadMetadata(certName)

		// If cert exists and has a private key, check if it needs updating
		if existingMeta != nil {
			// Already have this cert, check if key is present
			existingKey, _ := store.LoadPrivateKey(certName)
			if existingKey != "" {
				continue
			}
			// Key is missing — re-download
			fmt.Printf("  %s: private key missing, re-downloading...\n", certName)
		}

		// Download the full result including private key
		includeKey := true
		result, err := jobClient.GetJobResult(ctx, &lcmV1.GetJobResultRequest{
			JobId:             job.GetJobId(),
			IncludePrivateKey: &includeKey,
		})
		if err != nil {
			fmt.Printf("  %s: failed to get job result: %v\n", certName, err)
			continue
		}

		if result.GetStatus() != lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED {
			continue
		}

		certPEM := result.GetCertificatePem()
		if certPEM == "" {
			fmt.Printf("  %s: no certificate PEM in job result\n", certName)
			continue
		}

		keyPEM := result.GetPrivateKeyPem()
		caCertPEM := result.GetCaCertificatePem()

		isRenewal := existingMeta != nil
		previousSerial := ""
		renewalCount := 0
		if isRenewal {
			previousSerial = existingMeta.SerialNumber
			renewalCount = existingMeta.RenewalCount + 1
		}

		var expiresAt time.Time
		if result.GetExpiresAt() != nil {
			expiresAt = result.GetExpiresAt().AsTime()
		}
		var issuedAt time.Time
		if result.GetIssuedAt() != nil {
			issuedAt = result.GetIssuedAt().AsTime()
		}

		metadata := &storage.CertMetadata{
			Name:           certName,
			CommonName:     certName,
			SerialNumber:   result.GetSerialNumber(),
			IssuedAt:       issuedAt,
			ExpiresAt:      expiresAt,
			IssuerName:     job.GetIssuerName(),
			PreviousSerial: previousSerial,
			RenewalCount:   renewalCount,
		}

		if err := store.SaveCertificate(certName, certPEM, keyPEM, caCertPEM, metadata); err != nil {
			fmt.Printf("  %s: failed to save: %v\n", certName, err)
			continue
		}

		action := "downloaded"
		if isRenewal {
			action = "renewed"
		}
		fmt.Printf("  %s: %s (issuer: %s, serial: %s)\n", certName, action, job.GetIssuerName(), result.GetSerialNumber())
		updatedCount++

		// Run deploy hook using a minimal CertificateInfo for compatibility
		certInfo := &lcmV1.CertificateInfo{
			Name:         certName,
			CommonName:   certName,
			SerialNumber: result.GetSerialNumber(),
			IssuerName:   job.GetIssuerName(),
			ExpiresAt:    result.GetExpiresAt(),
			IssuedAt:     result.GetIssuedAt(),
		}
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
