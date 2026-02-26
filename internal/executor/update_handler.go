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

	// Check for update
	fmt.Println("  Checking for updates...")
	result, err := updater.CheckForUpdate(ctx, currentVersion)
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
	fmt.Printf("  Updating v%s -> v%s...\n", result.CurrentVersion, result.LatestVersion)
	if err := updater.DownloadAndApply(ctx, result); err != nil {
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
