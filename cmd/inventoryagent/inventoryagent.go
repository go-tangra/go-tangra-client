// Package inventoryagent is the `inventory-agent` command: install the go-tangra
// v4 inventory agent when missing and enroll it with an auto-enrollment key.
package inventoryagent

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/invagent"
)

// Command installs and enrolls the inventory agent now.
var Command = &cobra.Command{
	Use:           "inventory-agent",
	Short:         "Install the go-tangra inventory agent if missing and auto-enroll it",
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error
	Long: `Make sure the go-tangra v4 inventory agent is installed and enrolled.

When no enrolled agent is found, the agent package (deb/rpm) is downloaded
from the go-tangra-inventory GitHub release, verified against the signed
release manifest, installed, configured with the auto-enrollment key and
started. The daemon does the same at start-up and after self-updates.

Configuration (/etc/tangra-client/config.yaml):
  inventory-ingest: "portal.example.org:9977"
  inventory-auto-enroll-key-id: "ak_..."
  inventory-auto-enroll-key-file: "/etc/tangra-client/inventory-auto-enroll.key"   # or inventory-auto-enroll-key
  inventory-ca-file: ""            # optional CA of the ingest certificate
  inventory-agent-version: latest  # or a release such as 4.5.1
  disable-inventory-agent: false
`,
	RunE: func(*cobra.Command, []string) error {
		out, err := cmd.EnsureInventoryAgent(context.Background())
		if err != nil {
			return err
		}
		switch out {
		case invagent.OutcomeNotConfigured:
			return fmt.Errorf("automatic enrollment is not configured (inventory-ingest, inventory-auto-enroll-key-id, inventory-auto-enroll-key[-file]) or disabled")
		case invagent.OutcomeEnrolled:
			fmt.Println("Inventory agent: already enrolled")
		default:
			fmt.Printf("Inventory agent: %s\n", out)
		}
		return nil
	},
}
