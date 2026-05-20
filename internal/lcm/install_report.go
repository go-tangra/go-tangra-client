package lcm

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
)

// reportInstallResult tells LCM that the agent has applied (or failed to apply)
// a certificate locally. This is what allows the deployer's tangra-client
// provider Verify to confirm the push landed.
//
// Best-effort: failure to report is logged but never propagated, since reporting
// is informational and must not block the install path.
func reportInstallResult(
	ctx context.Context,
	grpcClient lcmV1.LcmClientServiceClient,
	certName string,
	certPEM string,
	serialNumber string,
	fingerprint string,
	status lcmV1.InstalledCertificateStatus,
	message string,
) {
	if grpcClient == nil || certName == "" {
		return
	}

	// Backfill fingerprint from the certificate PEM when the server-supplied
	// CertificateInfo didn't include one (e.g. deployer pushes that carry only
	// the bytes).
	if fingerprint == "" && certPEM != "" {
		if fp, err := fingerprintFromPEM(certPEM); err == nil {
			fingerprint = fp
		}
	}

	req := &lcmV1.ReportInstalledCertificateRequest{
		Name:   certName,
		Status: status,
	}
	if serialNumber != "" {
		req.SerialNumber = &serialNumber
	}
	if fingerprint != "" {
		req.FingerprintSha256 = &fingerprint
	}
	if message != "" {
		req.Message = &message
	}

	if _, err := grpcClient.ReportInstalledCertificate(ctx, req); err != nil {
		fmt.Printf("  Warning: failed to report install state for %s: %v\n", certName, err)
	}
}

// fingerprintFromPEM returns the lowercase hex SHA-256 fingerprint of the
// first certificate block found in pemBytes.
func fingerprintFromPEM(pemBytes string) (string, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}
