package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/viper"

	"github.com/go-tangra/go-tangra-client/internal/invagent"
	"github.com/go-tangra/go-tangra-client/internal/updater"
)

// InventoryReleaseAPI is the GitHub API of the inventory agent releases.
const InventoryReleaseAPI = "https://api.github.com/repos/go-tangra/go-tangra-inventory"

// InventoryAgentSettings returns the automatic enrollment settings of the
// go-tangra v4 inventory agent from the configuration.
func InventoryAgentSettings() invagent.Settings {
	return invagent.Settings{
		Ingest:      viper.GetString("inventory-ingest"),
		KeyID:       viper.GetString("inventory-auto-enroll-key-id"),
		Key:         viper.GetString("inventory-auto-enroll-key"),
		KeyFile:     viper.GetString("inventory-auto-enroll-key-file"),
		CAFile:      viper.GetString("inventory-ca-file"),
		ServerName:  viper.GetString("inventory-server-name"),
		Version:     viper.GetString("inventory-agent-version"),
		ReleaseKeys: viper.GetString("inventory-agent-release-keys"),
	}
}

// EnsureInventoryAgent installs and auto-enrolls the inventory agent when
// it is configured (see internal/invagent). It is best effort: problems are
// reported, never fatal for the caller. Containers are skipped.
func EnsureInventoryAgent(ctx context.Context) (invagent.Outcome, error) {
	s := InventoryAgentSettings()
	if !s.Configured() || viper.GetBool("disable-inventory-agent") {
		return invagent.OutcomeNotConfigured, nil
	}
	if env := updater.DetectEnvironment(); env.IsDocker || env.IsK8s {
		return invagent.OutcomeUnsupported, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	in := invagent.New(invagent.Source{HTTP: &http.Client{Timeout: 5 * time.Minute}, API: InventoryReleaseAPI})
	out, err := in.Ensure(ctx, s)
	if err != nil {
		fmt.Printf("Inventory agent: %v\n", err)
	}
	return out, err
}
