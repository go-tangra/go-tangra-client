package executor

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-actions/engine"
	"github.com/go-tangra/go-tangra-actions/jsruntime"
	"github.com/go-tangra/go-tangra-actions/system"
	"github.com/go-tangra/go-tangra-actions/workflow"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
)

// handleActionCommand runs a go-tangra-actions workflow pushed by the executor,
// streaming its output back live (GitHub-Actions style) via StreamExecutionOutput
// and reporting the final result. Actions referenced by the workflow are resolved
// from the executor's action repository.
func handleActionCommand(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	command *executorV1.ExecutionCommand,
	timeout time.Duration,
) error {
	execID := command.GetExecutionId()
	name := command.GetScriptName()
	fmt.Printf("\n[%s] Executor: Received workflow %q (execution %s)\n",
		time.Now().Format("15:04:05"), name, execID)

	wf, err := workflow.Parse([]byte(command.GetWorkflow()))
	if err != nil {
		msg := fmt.Sprintf("invalid workflow: %v", err)
		fmt.Printf("  %s\n", msg)
		reportWorkflowResult(ctx, grpcClient, execID, 1, msg, 0)
		return nil
	}

	// Open the live output stream. If it cannot be opened we still run the
	// workflow; output is then only persisted via the final ReportResult.
	stream, streamErr := grpcClient.StreamExecutionOutput(ctx)
	if streamErr != nil {
		fmt.Printf("  Warning: live output stream unavailable (%v); running without streaming\n", streamErr)
		stream = nil
	}

	var sendMu sync.Mutex
	sink := func(ev engine.OutputEvent) {
		os.Stdout.Write(ev.Data) // echo locally
		if stream == nil {
			return
		}
		sendMu.Lock()
		defer sendMu.Unlock()
		_ = stream.Send(&executorV1.ExecutionOutputChunk{
			ExecutionId: execID,
			Stream:      ev.Stream.String(),
			Data:        ev.Data,
			Job:         ev.Job,
			Step:        ev.Step,
		})
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runner := engine.New(engine.Options{
		System:        system.NewReal(),
		Resolver:      newExecutorResolver(grpcClient),
		ScriptRuntime: jsruntime.New(),
		Output:        sink,
	})

	start := time.Now()
	result, runErr := runner.Run(runCtx, wf, command.GetInputs())
	duration := time.Since(start).Milliseconds()

	if stream != nil {
		if _, cErr := stream.CloseAndRecv(); cErr != nil {
			fmt.Printf("  Warning: closing output stream: %v\n", cErr)
		}
	}

	exitCode := int32(0)
	switch {
	case runErr != nil:
		exitCode = 1
		fmt.Printf("  workflow error: %v (%dms)\n", runErr, duration)
	case result == nil || !result.Success:
		exitCode = 1
		fmt.Printf("  workflow failed (%dms)\n", duration)
	default:
		fmt.Printf("  workflow succeeded (%dms)\n", duration)
	}

	// Output already streamed and persisted; send empty output to preserve it.
	reportWorkflowResult(ctx, grpcClient, execID, exitCode, "", duration)
	return nil
}

func reportWorkflowResult(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	execID string,
	exitCode int32,
	output string,
	durationMs int64,
) {
	_, err := grpcClient.ReportResult(ctx, &executorV1.ReportResultRequest{
		ExecutionId: execID,
		ExitCode:    exitCode,
		Output:      output,
		DurationMs:  durationMs,
	})
	if err != nil {
		fmt.Printf("  Failed to report workflow result: %v\n", err)
	}
}
