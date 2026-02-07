package registration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/go-tangra/go-tangra-client/internal/machine"
	"github.com/go-tangra/go-tangra-client/pkg/client"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
)

// Config holds the parameters needed for client registration.
type Config struct {
	ServerAddr string
	ClientID   string
	Hostname   string
	CertFile   string
	KeyFile    string
	CAFile     string
	Secret     string
	KeySize    int
}

// Register performs client registration with the LCM server.
// It generates a key pair, sends a registration request, and saves the issued credentials.
// Returns the tenant ID from the server response, or an error.
func Register(ctx context.Context, cfg *Config) (uint32, error) {
	if cfg.KeySize == 0 {
		cfg.KeySize = 2048
	}
	if cfg.Hostname == "" {
		cfg.Hostname = machine.GetHostname()
	}

	fmt.Printf("Registering client '%s' with server '%s'...\n", cfg.ClientID, cfg.ServerAddr)

	// Generate RSA key pair
	fmt.Printf("Generating %d-bit RSA key pair...\n", cfg.KeySize)
	privateKey, err := rsa.GenerateKey(rand.Reader, cfg.KeySize)
	if err != nil {
		return 0, fmt.Errorf("failed to generate private key: %w", err)
	}

	if err := savePrivateKey(privateKey, cfg.KeyFile); err != nil {
		return 0, fmt.Errorf("failed to save private key: %w", err)
	}
	fmt.Printf("Private key saved to: %s\n", cfg.KeyFile)

	// Encode public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	dnsNames := []string{cfg.Hostname}
	ipAddresses := machine.GetLocalIPAddresses()
	metadata := machine.GetMetadata()

	// Connect to server (TLS without client cert for registration)
	fmt.Println("Connecting to server...")
	conn, err := client.CreateTLSConnectionWithoutClientCert(cfg.ServerAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	grpcClient := lcmV1.NewLcmClientServiceClient(conn)

	req := &lcmV1.CreateLcmClientRequest{
		ClientId:     cfg.ClientID,
		Hostname:     cfg.Hostname,
		SharedSecret: &cfg.Secret,
		PublicKey:     string(pubKeyPEM),
		DnsNames:     dnsNames,
		IpAddresses:  ipAddresses,
		Metadata:     metadata,
	}

	fmt.Println("Sending registration request...")
	resp, err := grpcClient.RegisterLcmClient(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("registration failed: %w", err)
	}

	var tenantID uint32
	if resp.Client != nil && resp.Client.TenantId != nil {
		tenantID = resp.Client.GetTenantId()
		fmt.Printf("Registered with tenant ID: %d\n", tenantID)
	}

	if resp.Certificate == nil {
		return tenantID, fmt.Errorf("registration completed but no certificate in response — may be pending approval")
	}

	status := resp.Certificate.GetStatus()

	switch status {
	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_ISSUED:
		fmt.Println("Certificate issued successfully!")

		certPEM := resp.Certificate.GetCertificatePem()
		if certPEM != "" {
			if err := os.WriteFile(cfg.CertFile, []byte(certPEM), 0600); err != nil {
				return tenantID, fmt.Errorf("failed to save certificate: %w", err)
			}
			fmt.Printf("Certificate saved to: %s\n", cfg.CertFile)
		}

		caCertPEM := resp.GetCaCertificate()
		if caCertPEM != "" {
			if err := os.WriteFile(cfg.CAFile, []byte(caCertPEM), 0644); err != nil {
				return tenantID, fmt.Errorf("failed to save CA certificate: %w", err)
			}
			fmt.Printf("CA certificate saved to: %s\n", cfg.CAFile)
		}

		fmt.Println("Registration complete!")
		return tenantID, nil

	case lcmV1.ClientCertificateStatus_CLIENT_CERT_STATUS_PENDING:
		requestID := resp.Certificate.GetRequestId()
		return tenantID, fmt.Errorf("certificate request is pending approval (request ID: %s)", requestID)

	default:
		return tenantID, fmt.Errorf("unexpected certificate status: %v", status)
	}
}

func savePrivateKey(key *rsa.PrivateKey, path string) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(path, keyPEM, 0600)
}
