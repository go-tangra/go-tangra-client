package executor

import (
	"context"
	"fmt"
	"io"
	"time"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
)

// RunStreamer connects to the executor StreamCommands RPC, processes execution
// commands, and reconnects with backoff on disconnect.
func RunStreamer(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	hashStore *HashStore,
	clientID string,
	timeout time.Duration,
	reconnectInterval time.Duration,
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err := runStreamLoop(ctx, grpcClient, hashStore, clientID, timeout)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Printf("Executor: Stream disconnected: %v\n", err)
		}

		fmt.Printf("Executor: Reconnecting in %s...\n", reconnectInterval)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(reconnectInterval):
		}
	}
}

func runStreamLoop(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	hashStore *HashStore,
	clientID string,
	timeout time.Duration,
) error {
	stream, err := grpcClient.StreamCommands(ctx, &executorV1.StreamCommandsRequest{
		ClientId: clientID,
	})
	if err != nil {
		return fmt.Errorf("failed to start stream: %w", err)
	}

	fmt.Println("Executor: Connected, waiting for commands...")

	for {
		command, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		handleExecutionCommand(ctx, grpcClient, hashStore, command, timeout)
	}
}

func handleExecutionCommand(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	hashStore *HashStore,
	command *executorV1.ExecutionCommand,
	timeout time.Duration,
) {
	commandID := command.GetCommandId()
	executionID := command.GetExecutionId()
	scriptID := command.GetScriptId()
	scriptName := command.GetScriptName()
	scriptType := command.GetScriptType()
	content := command.GetContent()
	serverHash := command.GetContentHash()

	// Verify content hash locally
	contentHash := computeContentHash(content)
	if contentHash != serverHash {
		fmt.Printf("\n[%s] Executor: Hash mismatch for script %q (server=%s local=%s), rejecting\n",
			time.Now().Format("15:04:05"), scriptName, serverHash[:12], contentHash[:12])
		reason := "hash_mismatch"
		_, _ = grpcClient.AckCommand(ctx, &executorV1.AckCommandRequest{
			CommandId:       commandID,
			Accepted:        false,
			RejectionReason: &reason,
		})
		return
	}

	fmt.Printf("\n[%s] Executor: Received command for script %q (hash: %s)\n",
		time.Now().Format("15:04:05"),
		scriptName,
		contentHash[:12],
	)

	// Check hash store
	if !hashStore.IsApproved(scriptID, contentHash) {
		oldHash := hashStore.GetHash(scriptID)
		reason := "hash not approved"
		if oldHash != "" {
			reason = fmt.Sprintf("hash changed (old: %s, new: %s)", oldHash[:12], contentHash[:12])
		}

		fmt.Printf("  Rejecting: %s\n", reason)

		// Ack with rejection
		_, err := grpcClient.AckCommand(ctx, &executorV1.AckCommandRequest{
			CommandId:       commandID,
			Accepted:        false,
			RejectionReason: &reason,
		})
		if err != nil {
			fmt.Printf("  Failed to ack rejection: %v\n", err)
		}
		return
	}

	fmt.Printf("  Hash approved, executing...\n")

	// Execute
	startTime := time.Now()
	exitCode, stdout, stderr, err := executeScript(ctx, scriptType, content, timeout)
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		fmt.Printf("  Execution error: %v\n", err)
		// Still report what we have
	}

	fmt.Printf("  Exit code: %d, Duration: %dms\n", exitCode, duration)

	// Report result
	_, reportErr := grpcClient.ReportResult(ctx, &executorV1.ReportResultRequest{
		ExecutionId: executionID,
		ExitCode:    exitCode,
		Output:      stdout,
		ErrorOutput: stderr,
		DurationMs:  duration,
	})
	if reportErr != nil {
		fmt.Printf("  Failed to report result: %v\n", reportErr)
	}
}
