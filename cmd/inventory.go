package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"

	"github.com/go-tangra/go-tangra-client/internal/invagent"
	"github.com/go-tangra/go-tangra-client/internal/updater"
	"github.com/go-tangra/go-tangra-client/pkg/client"
)

// InventoryReleaseAPI is the GitHub API of the inventory agent releases.
const InventoryReleaseAPI = "https://api.github.com/repos/go-tangra/go-tangra-inventory"

// localInventorySettings returns the inventory agent settings set in the
// client configuration (they take precedence over the executor's).
func localInventorySettings() invagent.Settings {
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

// InventoryAgentSettings resolves the automatic enrollment settings: the
// local configuration when it sets any of them, otherwise the platform
// settings the executor hands out (Executor > Clients > Inventory agent).
// A zero value means "not configured".
func InventoryAgentSettings(ctx context.Context) (invagent.Settings, string, error) {
	if s := localInventorySettings(); s.Configured() {
		return s, "local configuration", nil
	}
	if viper.GetBool("disable-executor") || GetExecutorServerAddr() == "" {
		return invagent.Settings{}, "", nil
	}
	conn, err := client.CreateMTLSConnection(GetExecutorServerAddr(), GetCertFile(), GetKeyFile(), GetCAFile())
	if err != nil {
		return invagent.Settings{}, "", fmt.Errorf("executor: %w", err)
	}
	defer conn.Close()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := executorV1.NewExecutorClientServiceClient(conn).GetInventoryAgentConfig(cctx, &executorV1.GetInventoryAgentConfigRequest{ClientId: GetClientID()})
	if status.Code(err) == codes.Unimplemented {
		return invagent.Settings{}, "", nil // executor predates the setting
	}
	if err != nil {
		return invagent.Settings{}, "", fmt.Errorf("executor: %w", err)
	}
	if !resp.GetEnabled() {
		return invagent.Settings{}, "", nil
	}
	return invagent.Settings{
		Ingest:      resp.GetIngestEndpoint(),
		KeyID:       resp.GetKeyId(),
		Key:         resp.GetKeySecret(),
		CAPEM:       resp.GetCaPem(),
		ServerName:  resp.GetServerName(),
		Version:     resp.GetAgentVersion(),
		ReleaseKeys: viper.GetString("inventory-agent-release-keys"),
	}, "executor", nil
}

// EnsureInventoryAgent installs and auto-enrolls the inventory agent when
// it is configured (see internal/invagent). It is best effort: problems are
// reported, never fatal for the caller. Containers are skipped.
func EnsureInventoryAgent(ctx context.Context) (invagent.Outcome, error) {
	if viper.GetBool("disable-inventory-agent") {
		return invagent.OutcomeNotConfigured, nil
	}
	if env := updater.DetectEnvironment(); env.IsDocker || env.IsK8s {
		return invagent.OutcomeUnsupported, nil
	}
	s, source, err := InventoryAgentSettings(ctx)
	if err != nil {
		fmt.Printf("Inventory agent: settings unavailable: %v\n", err)
		return invagent.OutcomeNotConfigured, err
	}
	if !s.Configured() {
		return invagent.OutcomeNotConfigured, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	in := invagent.New(invagent.Source{HTTP: &http.Client{Timeout: 5 * time.Minute}, API: InventoryReleaseAPI})
	out, err := in.Ensure(ctx, s)
	if err != nil {
		fmt.Printf("Inventory agent (settings from %s): %v\n", source, err)
	}
	return out, err
}
