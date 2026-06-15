package update

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/updater"
	"github.com/go-tangra/go-tangra-client/pkg/client"
)

var checkOnly bool

// Command is the update command.
var Command = &cobra.Command{
	Use:   "update",
	Short: "Update tangra-client to the latest version",
	Long: `Check for and apply updates from GitHub Releases.

Uses checksum verification to ensure binary integrity.

Examples:
  tangra-client update          # Download and apply latest update
  tangra-client update --check  # Only check if an update is available
`,
	RunE: runUpdate,
}

func init() {
	Command.Flags().BoolVar(&checkOnly, "check", false, "Only check for updates, don't download")
}

func runUpdate(_ *cobra.Command, _ []string) error {
	info := cmd.GetBuildInfo()

	if info.Version == "dev" {
		return fmt.Errorf("cannot update a development build; install a release binary first")
	}

	env := updater.DetectEnvironment()

	if env.IsDocker || env.IsK8s {
		envName := "Docker"
		if env.IsK8s {
			envName = "Kubernetes"
		}
		return fmt.Errorf("self-update is not supported in %s; update the container image instead", envName)
	}

	if env.IsPackaged {
		fmt.Println("Warning: this binary appears to be package-managed (/usr/local/bin or /usr/bin).")
		fmt.Println("Consider updating via your package manager (apt upgrade / dnf upgrade) instead.")
		fmt.Println()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	fmt.Printf("Current version: %s\n", info.Version)
	fmt.Println("Checking for updates...")

	// Prefer the executor as the update source so the whole fleet updates
	// through it without each client hitting the GitHub API. Falls back to
	// GitHub when the executor is unreachable or has nothing cached.
	execClient, closeExec := dialExecutor()
	if closeExec != nil {
		defer closeExec()
	}

	result, viaExecutor, err := checkForUpdate(ctx, execClient, info.Version)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	if !result.UpdateAvail {
		fmt.Printf("Already up to date (v%s)\n", result.CurrentVersion)
		return nil
	}

	source := "GitHub"
	if viaExecutor {
		source = "executor"
	}
	fmt.Printf("Update available: v%s -> v%s (via %s)\n", result.CurrentVersion, result.LatestVersion, source)
	if result.ReleaseURL != "" {
		fmt.Printf("Release: %s\n", result.ReleaseURL)
	}

	if checkOnly {
		return nil
	}

	if viaExecutor {
		err = updater.DownloadAndApplyViaExecutor(ctx, execClient, result)
	} else {
		err = updater.DownloadAndApply(ctx, result)
	}
	if err != nil {
		return err
	}

	if env.IsSystemd {
		fmt.Println()
		fmt.Println("Hint: restart the service to use the new version:")
		fmt.Println("  sudo systemctl restart tangra-client")
	}

	return nil
}

// dialExecutor opens a best-effort mTLS connection to the executor. It returns
// a nil client (and nil closer) when the executor is not configured or the
// certificates are missing, in which case the caller falls back to GitHub.
func dialExecutor() (executorV1.ExecutorClientServiceClient, func()) {
	addr := cmd.GetExecutorServerAddr()
	if addr == "" {
		return nil, nil
	}

	conn, err := client.CreateMTLSConnection(addr, cmd.GetCertFile(), cmd.GetKeyFile(), cmd.GetCAFile())
	if err != nil {
		// Not fatal — we just fall back to GitHub.
		return nil, nil
	}

	return executorV1.NewExecutorClientServiceClient(conn), func() { _ = conn.Close() }
}

// checkForUpdate prefers the executor source, falling back to GitHub. The bool
// return reports whether the result came from the executor.
func checkForUpdate(
	ctx context.Context,
	execClient executorV1.ExecutorClientServiceClient,
	currentVersion string,
) (*updater.UpdateResult, bool, error) {
	if execClient != nil {
		result, err := updater.CheckViaExecutor(ctx, execClient, currentVersion)
		if err == nil {
			return result, true, nil
		}
		if !errors.Is(err, updater.ErrReleaseNotCached) {
			fmt.Printf("Executor update source unavailable (%v), falling back to GitHub\n", err)
		}
	}

	result, err := updater.CheckForUpdate(ctx, currentVersion)
	if err != nil {
		return nil, false, err
	}
	return result, false, nil
}
