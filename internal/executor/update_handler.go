package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"

	"github.com/go-tangra/go-tangra-client/internal/updater"
)

// ErrRestartRequested is returned when the client has updated itself and needs to restart.
var ErrRestartRequested = errors.New("restart requested after update")

func handleUpdateCommand(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	command *executorV1.ExecutionCommand,
	currentVersion string,
) error {
	commandID := command.GetCommandId()
	targetVersion := command.GetTargetVersion()

	fmt.Printf("\n[%s] Executor: Received client update command (target: %s)\n",
		time.Now().Format("15:04:05"), versionLabel(targetVersion))

	// Reject if running in a container
	env := updater.DetectEnvironment()
	if env.IsDocker || env.IsK8s {
		envName := "Docker"
		if env.IsK8s {
			envName = "Kubernetes"
		}
		msg := fmt.Sprintf("self-update not supported in %s environment", envName)
		fmt.Printf("  Update rejected: %s\n", msg)
		ackUpdate(ctx, grpcClient, commandID, false, msg)
		return nil
	}

	if currentVersion == "dev" {
		msg := "cannot update a development build"
		fmt.Printf("  Update rejected: %s\n", msg)
		ackUpdate(ctx, grpcClient, commandID, false, msg)
		return nil
	}

	// Check for update — prefer the executor (avoids GitHub rate limits across
	// the fleet), falling back to GitHub when the executor has nothing cached.
	fmt.Println("  Checking for updates...")
	result, viaExecutor, err := checkForUpdate(ctx, grpcClient, currentVersion)
	if err != nil {
		msg := fmt.Sprintf("update check failed: %v", err)
		fmt.Printf("  %s\n", msg)
		ackUpdate(ctx, grpcClient, commandID, false, msg)
		return nil
	}

	if !result.UpdateAvail {
		msg := fmt.Sprintf("already up to date v%s", result.CurrentVersion)
		fmt.Printf("  %s\n", msg)
		ackUpdate(ctx, grpcClient, commandID, true, msg)
		return nil
	}

	// Download and apply
	source := "GitHub"
	if viaExecutor {
		source = "executor"
	}
	fmt.Printf("  Updating v%s -> v%s (via %s)...\n", result.CurrentVersion, result.LatestVersion, source)
	if err := downloadAndApply(ctx, grpcClient, result, viaExecutor); err != nil {
		msg := fmt.Sprintf("update failed: %v", err)
		fmt.Printf("  %s\n", msg)
		ackUpdate(ctx, grpcClient, commandID, false, msg)
		return nil
	}

	// Report success before restarting
	msg := fmt.Sprintf("updated v%s -> v%s", result.CurrentVersion, result.LatestVersion)
	fmt.Printf("  %s\n", msg)
	ackUpdate(ctx, grpcClient, commandID, true, msg)

	return ErrRestartRequested
}

// checkForUpdate tries the executor first and falls back to GitHub. The bool
// return reports whether the result came from the executor (and therefore must
// be downloaded from it too).
func checkForUpdate(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	currentVersion string,
) (*updater.UpdateResult, bool, error) {
	result, err := updater.CheckViaExecutor(ctx, grpcClient, currentVersion)
	if err == nil {
		return result, true, nil
	}
	if !errors.Is(err, updater.ErrReleaseNotCached) {
		fmt.Printf("  Executor update source unavailable (%v), falling back to GitHub\n", err)
	}

	result, err = updater.CheckForUpdate(ctx, currentVersion)
	if err != nil {
		return nil, false, err
	}
	return result, false, nil
}

// downloadAndApply downloads from the executor when viaExecutor is set,
// otherwise from GitHub.
func downloadAndApply(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	result *updater.UpdateResult,
	viaExecutor bool,
) error {
	if viaExecutor {
		return updater.DownloadAndApplyViaExecutor(ctx, grpcClient, result)
	}
	return updater.DownloadAndApply(ctx, result)
}

// ackUpdate sends the update result via AckCommand. There is no execution log
// for update commands, so ReportResult cannot be used.
func ackUpdate(ctx context.Context, grpcClient executorV1.ExecutorClientServiceClient, commandID string, ok bool, message string) {
	_, err := grpcClient.AckCommand(ctx, &executorV1.AckCommandRequest{
		CommandId:       commandID,
		Accepted:        ok,
		RejectionReason: &message,
	})
	if err != nil {
		fmt.Printf("  Failed to ack update result: %v\n", err)
	}
}

func versionLabel(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}
