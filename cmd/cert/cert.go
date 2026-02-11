package cert

import (
	"github.com/spf13/cobra"
)

// Command is the cert command group
var Command = &cobra.Command{
	Use:   "cert",
	Short: "Certificate management commands",
	Long: `Manage mTLS certificates via the LCM server.

Subcommands:
  request   Request a new mTLS certificate

Example:
  tangra-client cert request --common-name myhost.example.com
  tangra-client cert request --common-name myhost.example.com --dns "*.example.com" --issuer my-issuer
`,
}

func init() {
	Command.AddCommand(requestCmd)
}
