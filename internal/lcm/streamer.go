package lcm

import (
	"context"
	"fmt"
	"io"
	"time"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"

	"github.com/go-tangra/go-tangra-client/internal/hook"
	"github.com/go-tangra/go-tangra-client/internal/storage"
	"github.com/go-tangra/go-tangra-client/pkg/backoff"
)

// RunStreamer connects to the LCM streaming RPC, handles certificate update events,
// and reconnects with exponential backoff on disconnect.
func RunStreamer(ctx context.Context, grpcClient lcmV1.LcmClientServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig, fallbackInterval time.Duration) error {
	bo := backoff.New()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := runStreamLoop(ctx, grpcClient, store, hookRunner, hookConfig)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Printf("LCM: Stream disconnected: %v\n", err)
		}

		// On disconnect, do a fallback sync
		fmt.Println("LCM: Performing fallback sync...")
		if _, err := SyncCertificates(ctx, grpcClient, store, hookRunner, hookConfig); err != nil {
			fmt.Printf("LCM: Fallback sync failed: %v\n", err)
		} else {
			// Sync succeeded, connection is healthy — reset backoff
			bo.Reset()
		}

		fmt.Print("LCM: ")
		if _, cancelled := bo.Wait(ctx); cancelled {
			return nil
		}
	}
}

func runStreamLoop(ctx context.Context, grpcClient lcmV1.LcmClientServiceClient, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig) error {
	stream, err := grpcClient.StreamCertificateUpdates(ctx, &lcmV1.StreamCertificateUpdatesRequest{})
	if err != nil {
		return fmt.Errorf("failed to start stream: %w", err)
	}

	for {
		event, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		handleUpdateEvent(ctx, event, store, hookRunner, hookConfig)
	}
}

func handleUpdateEvent(ctx context.Context, event *lcmV1.CertificateUpdateEvent, store *storage.CertStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig) {
	certInfo := event.GetCertificate()
	if certInfo == nil {
		return
	}

	certName := getCertName(certInfo)
	eventType := event.GetEventType()

	switch eventType {
	case lcmV1.CertificateUpdateType_CERTIFICATE_ISSUED,
		lcmV1.CertificateUpdateType_CERTIFICATE_RENEWED:

		fmt.Printf("\n[%s] Certificate %s: %s\n",
			time.Now().Format("15:04:05"),
			eventType.String(),
			certName)

		certPEM := certInfo.GetCertificatePem()
		if certPEM == "" {
			fmt.Printf("  No certificate PEM in event, will sync on next interval\n")
			return
		}

		existingMeta, _ := store.LoadMetadata(certName)
		isRenewal := existingMeta != nil
		previousSerial := ""
		renewalCount := 0
		if isRenewal {
			previousSerial = existingMeta.SerialNumber
			renewalCount = existingMeta.RenewalCount + 1
		}

		keyPEM := ""
		if store.CertificateExists(certName) {
			keyPEM, _ = store.LoadPrivateKey(certName)
		}

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

		caCertPEM := event.GetCaCertificatePem()

		if err := store.SaveCertificate(certName, certPEM, keyPEM, caCertPEM, metadata); err != nil {
			fmt.Printf("  Failed to save: %v\n", err)
			return
		}
		fmt.Printf("  Saved to %s/live/%s/\n", store.BaseDir(), certName)

		runDeployHookForCert(ctx, hookRunner, hookConfig, store, certInfo, certName, isRenewal, expiresAt)

	case lcmV1.CertificateUpdateType_CERTIFICATE_REVOKED:
		fmt.Printf("\n[%s] Certificate REVOKED: %s\n",
			time.Now().Format("15:04:05"),
			certName)

	case lcmV1.CertificateUpdateType_CERTIFICATE_EXPIRING:
		fmt.Printf("\n[%s] Certificate EXPIRING SOON: %s\n",
			time.Now().Format("15:04:05"),
			certName)
	}
}
