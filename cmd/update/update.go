package update

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/updater"
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Printf("Current version: %s\n", info.Version)
	fmt.Println("Checking for updates...")

	result, err := updater.CheckForUpdate(ctx, info.Version)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	if !result.UpdateAvail {
		fmt.Printf("Already up to date (v%s)\n", result.CurrentVersion)
		return nil
	}

	fmt.Printf("Update available: v%s -> v%s\n", result.CurrentVersion, result.LatestVersion)
	fmt.Printf("Release: %s\n", result.ReleaseURL)

	if checkOnly {
		return nil
	}

	if err := updater.DownloadAndApply(ctx, result); err != nil {
		return err
	}

	if env.IsSystemd {
		fmt.Println()
		fmt.Println("Hint: restart the service to use the new version:")
		fmt.Println("  sudo systemctl restart tangra-client")
	}

	return nil
}
