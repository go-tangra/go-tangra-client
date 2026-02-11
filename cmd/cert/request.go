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
	outputDir    string
	wait         bool
)

var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Request a new mTLS certificate from the LCM server",
	Long: `Request a new mTLS certificate by submitting a certificate request to the LCM server.

The key pair is generated server-side by LCM. This command sends a certificate
request via LcmMtlsCertificateRequestService (requires mTLS authentication).
The request will appear as PENDING until approved by an admin.

Use --wait to poll until the certificate is approved and automatically download it.

Example:
  tangra-client cert request --common-name myhost.example.com
  tangra-client cert request --common-name myhost.example.com --dns "*.example.com" --dns api.example.com
  tangra-client cert request --common-name myhost.example.com --issuer my-issuer --validity-days 365
  tangra-client cert request --common-name myhost.example.com --wait
`,
	RunE: runCertRequest,
}

func init() {
	requestCmd.Flags().StringVar(&commonName, "common-name", "", "Common Name (CN) for the certificate (required)")
	requestCmd.Flags().StringSliceVar(&dnsNames, "dns", nil, "DNS Subject Alternative Names")
	requestCmd.Flags().StringSliceVar(&ipAddresses, "ip", nil, "IP Subject Alternative Names")
	requestCmd.Flags().StringVar(&issuerName, "issuer", "", "Issuer name for signing")
	requestCmd.Flags().Int32Var(&validityDays, "validity-days", 0, "Requested validity period in days (1-825)")
	requestCmd.Flags().StringVar(&outputDir, "output-dir", "", "Directory to save certificate files (default: <config-dir>/live/<common-name>/)")
	requestCmd.Flags().BoolVar(&wait, "wait", false, "Poll until certificate is approved, then download it")

	_ = requestCmd.MarkFlagRequired("common-name")
}

func runCertRequest(c *cobra.Command, args []string) error {
	clientID := cmd.GetClientID()
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

	// Build the certificate request (key generation happens server-side)
	certType := lcmV1.MtlsCertificateType_MTLS_CERT_TYPE_CLIENT
	req := &lcmV1.CreateMtlsCertificateRequestRequest{
		ClientId:    clientID,
		CommonName:  commonName,
		DnsNames:    dnsNames,
		IpAddresses: ipAddresses,
		CertType:    &certType,
	}
	if issuerName != "" {
		req.IssuerName = &issuerName
	}
	if validityDays > 0 {
		req.ValidityDays = &validityDays
	}

	// Submit the request
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Submitting certificate request...")
	grpcClient := lcmV1.NewLcmMtlsCertificateRequestServiceClient(conn)
	resp, err := grpcClient.CreateMtlsCertificateRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("certificate request failed: %w", err)
	}

	certReq := resp.GetMtlsCertificateRequest()
	requestID := certReq.GetRequestId()
	status := certReq.GetStatus()

	fmt.Printf("Request ID: %s\n", requestID)
	fmt.Printf("Status:     %s\n", requestStatusToString(status))

	if !wait {
		if status == lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_PENDING {
			fmt.Printf("\nCertificate request is pending approval.\n")
			fmt.Printf("Use --wait to poll until approved, or check status with:\n")
			fmt.Printf("  tangra-client status --request-id %s\n", requestID)
		}
		return nil
	}

	// Poll until issued, then download
	fmt.Println("\nWaiting for certificate approval...")
	return pollAndDownload(serverAddr, clientID, requestID)
}

func pollAndDownload(serverAddr, clientID, requestID string) error {
	// Use TLS without client cert for public endpoints (GetRequestStatus, DownloadClientCertificate)
	conn, err := client.CreateTLSConnectionWithoutClientCert(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to LCM server: %w", err)
	}
	defer conn.Close()

	grpcClient := lcmV1.NewLcmClientServiceClient(conn)

	pollInterval := 5 * time.Second
	maxWait := 30 * time.Minute
	deadline := time.Now().Add(maxWait)

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for certificate approval after %s", maxWait)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := grpcClient.GetRequestStatus(ctx, &lcmV1.GetRequestStatusRequest{
			RequestId: requestID,
			ClientId:  clientID,
		})
		cancel()

		if err != nil {
			fmt.Printf("  Error checking status: %v (retrying...)\n", err)
			time.Sleep(pollInterval)
			continue
		}

		switch resp.GetStatus() {
		case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED:
			fmt.Println("Certificate has been issued!")
			return downloadCert(grpcClient, clientID, requestID)

		case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_REVOKED:
			return fmt.Errorf("certificate request was rejected/revoked")

		case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING:
			fmt.Printf("  Status: PENDING (checking again in %s...)\n", pollInterval)

		default:
			fmt.Printf("  Status: %s (checking again in %s...)\n", resp.GetStatus(), pollInterval)
		}

		time.Sleep(pollInterval)
	}
}

func downloadCert(grpcClient lcmV1.LcmClientServiceClient, clientID, requestID string) error {
	outDir := outputDir
	if outDir == "" {
		outDir = filepath.Join(cmd.GetConfigDir(), "live", commonName)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := grpcClient.DownloadClientCertificate(ctx, &lcmV1.DownloadClientCertificateRequest{
		RequestId: requestID,
		ClientId:  clientID,
	})
	if err != nil {
		return fmt.Errorf("failed to download certificate: %w", err)
	}

	if resp.GetStatus() != lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED {
		return fmt.Errorf("unexpected certificate status: %s", resp.GetStatus())
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

	caCertPEM := resp.GetCaCertificatePem()
	if caCertPEM != "" {
		caPath := filepath.Join(outDir, "ca.pem")
		if err := os.WriteFile(caPath, []byte(caCertPEM), 0644); err != nil {
			return fmt.Errorf("failed to save CA certificate: %w", err)
		}
		fmt.Printf("CA certificate saved to: %s\n", caPath)
	}

	return nil
}

func requestStatusToString(status lcmV1.MtlsCertificateRequestStatus) string {
	switch status {
	case lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_PENDING:
		return "PENDING"
	case lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_APPROVED:
		return "APPROVED"
	case lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED:
		return "REJECTED"
	case lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED:
		return "ISSUED"
	case lcmV1.MtlsCertificateRequestStatus_MTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED:
		return "CANCELLED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}
}
