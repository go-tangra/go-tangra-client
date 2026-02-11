package cert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/pkg/client"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
)

var (
	commonName   string
	dnsNames     []string
	ipAddresses  []string
	issuerName   string
	validityDays int32
	keyType      string
	keySize      int32
	outputDir    string
	wait         bool
)

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Request a certificate from a registered issuer",
	Long: `Request a certificate from a registered issuer (e.g. ACME) via the LCM server.

This creates a Certificate Job on the LCM server. Key generation happens server-side.
The job is processed asynchronously — use --wait to poll until the certificate is
issued and automatically download it.

Requires mTLS authentication (run 'tangra-client register' first).

Example:
  tangra-client cert request --issuer lcm-frontend-acme --common-name myhost.example.com
  tangra-client cert request --issuer lcm-frontend-acme --common-name myhost.example.com --dns api.example.com
  tangra-client cert request --issuer lcm-frontend-acme --common-name myhost.example.com --wait
`,
	RunE: runCertRequest,
}

func init() {
	requestCmd.Flags().StringVar(&issuerName, "issuer", "", "Registered issuer name (required)")
	requestCmd.Flags().StringVar(&commonName, "common-name", "", "Common Name (CN) for the certificate (required)")
	requestCmd.Flags().StringSliceVar(&dnsNames, "dns", nil, "DNS Subject Alternative Names")
	requestCmd.Flags().StringSliceVar(&ipAddresses, "ip", nil, "IP Subject Alternative Names")
	requestCmd.Flags().Int32Var(&validityDays, "validity-days", 0, "Requested validity period in days (1-825)")
	requestCmd.Flags().StringVar(&keyType, "key-type", "", "Key type: rsa or ecdsa (server default if omitted)")
	requestCmd.Flags().Int32Var(&keySize, "key-size", 0, "Key size in bits (server default if omitted)")
	requestCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to save certificate files (default: <config-dir>/live/<common-name>/)")
	requestCmd.Flags().BoolVar(&wait, "wait", false, "Poll until certificate is issued, then download it")

	_ = requestCmd.MarkFlagRequired("issuer")
	_ = requestCmd.MarkFlagRequired("common-name")
}

func runCertRequest(c *cobra.Command, args []string) error {
	serverAddr := cmd.GetServerAddr()
	certFile := cmd.GetCertFile()
	keyFile := cmd.GetKeyFile()
	caFile := cmd.GetCAFile()

	// Connect to LCM via mTLS
	fmt.Printf("Connecting to LCM server %s via mTLS...\n", serverAddr)
	conn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to LCM server: %w", err)
	}
	defer conn.Close()

	// Build the certificate request
	req := &lcmV1.RequestCertificateRequest{
		IssuerName:  issuerName,
		CommonName:  commonName,
		DnsNames:    dnsNames,
		IpAddresses: ipAddresses,
	}
	if keyType != "" {
		req.KeyType = &keyType
	}
	if keySize > 0 {
		req.KeySize = &keySize
	}
	if validityDays > 0 {
		req.ValidityDays = &validityDays
	}

	// Submit the job
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Submitting certificate request...")
	grpcClient := lcmV1.NewLcmCertificateJobServiceClient(conn)
	resp, err := grpcClient.RequestCertificate(ctx, req)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w", err)
	}

	jobID := resp.GetJobId()
	status := resp.GetStatus()

	fmt.Printf("Job ID:  %s\n", jobID)
	fmt.Printf("Status:  %s\n", jobStatusToString(status))
	if msg := resp.GetMessage(); msg != "" {
		fmt.Printf("Message: %s\n", msg)
	}

	if !wait {
		if status == lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING ||
			status == lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING {
			fmt.Printf("\nCertificate job is in progress. Use --wait to poll until completed.\n")
		}
		return nil
	}

	// Poll until completed, then download
	fmt.Println("\nWaiting for certificate to be issued...")
	return pollAndDownload(grpcClient, jobID)
}

func pollAndDownload(grpcClient lcmV1.LcmCertificateJobServiceClient, jobID string) error {
	pollInterval := 5 * time.Second
	maxWait := 30 * time.Minute
	deadline := time.Now().Add(maxWait)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for certificate after %s", maxWait)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := grpcClient.GetJobStatus(ctx, &lcmV1.GetJobStatusRequest{
			JobId: jobID,
		})
		cancel()

		if err != nil {
			fmt.Printf("  Error checking status: %v (retrying...)\n", err)
			time.Sleep(pollInterval)
			continue
		}

		switch resp.GetStatus() {
		case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
			fmt.Println("Certificate has been issued!")
			return downloadResult(grpcClient, jobID)

		case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
			errMsg := resp.GetErrorMessage()
			return fmt.Errorf("certificate job failed: %s", errMsg)

		case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_CANCELLED:
			return fmt.Errorf("certificate job was cancelled")

		case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING:
			fmt.Printf("  Status: PROCESSING (checking again in %s...)\n", pollInterval)

		default:
			fmt.Printf("  Status: %s (checking again in %s...)\n", jobStatusToString(resp.GetStatus()), pollInterval)
		}

		time.Sleep(pollInterval)
	}
}

func downloadResult(grpcClient lcmV1.LcmCertificateJobServiceClient, jobID string) error {
	outDir := outputDir
	if outDir == "" {
		outDir = filepath.Join(cmd.GetConfigDir(), "live", commonName)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	includeKey := true
	resp, err := grpcClient.GetJobResult(ctx, &lcmV1.GetJobResultRequest{
		JobId:             jobID,
		IncludePrivateKey: &includeKey,
	})
	if err != nil {
		return fmt.Errorf("failed to get job result: %w", err)
	}

	if resp.GetStatus() != lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED {
		return fmt.Errorf("unexpected job status: %s", jobStatusToString(resp.GetStatus()))
	}

	certPEM := resp.GetCertificatePem()
	if certPEM == "" {
		return fmt.Errorf("server returned empty certificate")
	}

	certPath := filepath.Join(outDir, "cert.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	fmt.Printf("Certificate saved to: %s\n", certPath)

	if privKeyPEM := resp.GetPrivateKeyPem(); privKeyPEM != "" {
		keyPath := filepath.Join(outDir, "privkey.pem")
		if err := os.WriteFile(keyPath, []byte(privKeyPEM), 0600); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}
		fmt.Printf("Private key saved to: %s\n", keyPath)
	}

	if caCertPEM := resp.GetCaCertificatePem(); caCertPEM != "" {
		caPath := filepath.Join(outDir, "ca.pem")
		if err := os.WriteFile(caPath, []byte(caCertPEM), 0644); err != nil {
			return fmt.Errorf("failed to save CA certificate: %w", err)
		}
		fmt.Printf("CA certificate saved to: %s\n", caPath)
	}

	return nil
}

func jobStatusToString(status lcmV1.CertificateJobStatus) string {
	switch status {
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PENDING:
		return "PENDING"
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_PROCESSING:
		return "PROCESSING"
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_COMPLETED:
		return "COMPLETED"
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_FAILED:
		return "FAILED"
	case lcmV1.CertificateJobStatus_CERTIFICATE_JOB_STATUS_CANCELLED:
		return "CANCELLED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}
}
