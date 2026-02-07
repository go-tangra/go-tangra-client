package register

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/registration"
)

var (
	sharedSecret string
	hostname     string
	dnsNames     []string
	ipAddresses  []string
	keySize      int
)

// Command is the register command
var Command = &cobra.Command{
	Use:   "register",
	Short: "Register this client with the LCM server",
	Long: `Register this client with the LCM server and request a certificate.

This command generates a key pair, sends a registration request to the server,
and saves the issued certificate (or request ID for pending requests).

Example:
  tangra-client register --secret my-shared-secret
  tangra-client register --secret my-secret --hostname myhost.local
`,
	RunE: runRegister,
}

func init() {
	Command.Flags().StringVar(&sharedSecret, "secret", "", "Shared secret for authentication (required)")
	Command.Flags().StringVar(&hostname, "hostname", "", "Hostname for certificate (defaults to system hostname)")
	Command.Flags().StringSliceVar(&dnsNames, "dns", nil, "Additional DNS names for certificate")
	Command.Flags().StringSliceVar(&ipAddresses, "ip", nil, "Additional IP addresses for certificate")
	Command.Flags().IntVar(&keySize, "key-size", 2048, "RSA key size in bits (2048 or 4096)")

	_ = Command.MarkFlagRequired("secret")
}

func runRegister(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	configDir := cmd.GetConfigDir()
	clientID := cmd.GetClientID()
	serverAddr := cmd.GetServerAddr()

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	cfg := &registration.Config{
		ServerAddr: serverAddr,
		ClientID:   clientID,
		Hostname:   hostname,
		CertFile:   viper.GetString("cert"),
		KeyFile:    viper.GetString("key"),
		CAFile:     viper.GetString("ca"),
		Secret:     sharedSecret,
		KeySize:    keySize,
	}

	_, err := registration.Register(ctx, cfg)
	if err != nil {
		return err
	}

	fmt.Println("\nYou can now use authenticated commands.")
	return nil
}
