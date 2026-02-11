package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// SetDefaultCertPaths sets default certificate file paths if not provided
func SetDefaultCertPaths(certFile, keyFile, caFile *string, clientID string) {
	if *certFile == "" {
		*certFile = fmt.Sprintf("%s.crt", clientID)
	}
	if *keyFile == "" {
		*keyFile = fmt.Sprintf("%s.key", clientID)
	}
	if *caFile == "" {
		*caFile = "ca.crt"
	}
}

// SetDefaultCertPathsWithConfigDir sets default certificate file paths in the config directory
func SetDefaultCertPathsWithConfigDir(certFile, keyFile, caFile *string, clientID, configDir string) error {
	expandedConfigDir, err := expandPath(configDir)
	if err != nil {
		return fmt.Errorf("failed to expand config directory: %w", err)
	}

	if *certFile == "" {
		*certFile = filepath.Join(expandedConfigDir, fmt.Sprintf("%s.crt", clientID))
	}
	if *keyFile == "" {
		*keyFile = filepath.Join(expandedConfigDir, fmt.Sprintf("%s.key", clientID))
	}
	if *caFile == "" {
		*caFile = filepath.Join(expandedConfigDir, "ca.crt")
	}
	return nil
}

func expandPath(path string) (string, error) {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	} else if path == "~" {
		return os.UserHomeDir()
	}
	return path, nil
}

// ValidateCertFiles checks if certificate files exist and provides helpful error messages
func ValidateCertFiles(certFile, keyFile, caFile string) error {
	if certFile == "" {
		return fmt.Errorf("certificate file path is required")
	}
	if keyFile == "" {
		return fmt.Errorf("private key file path is required")
	}
	if caFile == "" {
		return fmt.Errorf("CA certificate file path is required")
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return fmt.Errorf("client certificate file '%s' not found. Run 'tangra-client register' first or provide --cert flag", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return fmt.Errorf("client private key file '%s' not found. Run 'tangra-client register' first or provide --key flag", keyFile)
	}
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate file '%s' not found. Run 'tangra-client register' first or provide --ca flag", caFile)
	}
	return nil
}

// CreateTLSConnectionWithoutClientCert creates a TLS connection without client certificate for registration
func CreateTLSConnectionWithoutClientCert(serverAddr string) (*grpc.ClientConn, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("server address is required")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server '%s' with TLS: %w", serverAddr, err)
	}

	return conn, nil
}

// CreateMTLSConnection creates a mutual TLS connection with client certificate
func CreateMTLSConnection(serverAddr, certFile, keyFile, caFile string) (*grpc.ClientConn, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("server address is required")
	}

	if err := ValidateCertFiles(certFile, keyFile, caFile); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate from '%s' and '%s': %w", certFile, keyFile, err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate from '%s': %w", caFile, err)
	}

	if len(caCert) == 0 {
		return nil, fmt.Errorf("CA certificate file '%s' is empty", caFile)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from '%s': invalid PEM format", caFile)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(serverAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server '%s' with mTLS: %w", serverAddr, err)
	}

	return conn, nil
}
