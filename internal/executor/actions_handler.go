package executor

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-actions/action"
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
	policy ActionsPolicy,
) error {
	execID := command.GetExecutionId()
	name := command.GetScriptName()
	fmt.Printf("\n[%s] Executor: Received workflow %q (execution %s)\n",
		time.Now().Format("15:04:05"), name, execID)

	// Defense-in-depth: even though the executor gates eligibility, refuse to run
	// workflows unless this host opted in via ACTIONS_ENABLED.
	if !policy.Enabled {
		msg := "action execution is not enabled on this host (set ACTIONS_ENABLED)"
		fmt.Printf("  %s\n", msg)
		reportWorkflowResult(ctx, grpcClient, execID, 1, msg+"\n", 0)
		return nil
	}

	wf, err := workflow.Parse([]byte(command.GetWorkflow()))
	if err != nil {
		msg := fmt.Sprintf("invalid workflow: %v", err)
		fmt.Printf("  %s\n", msg)
		reportWorkflowResult(ctx, grpcClient, execID, 1, msg, 0)
		return nil
	}

	// Restricted mode (ACTIONS_RESTRICTED, default on): only the native built-in
	// structured actions may run — no bash/`run:` steps, no scripted (JS/Lua)
	// actions, no external/composite actions. Build a registry of just the
	// allowlisted actions and refuse anything else up front. When unrestricted,
	// use the full builtin set plus the executor resolver and JS runtime.
	reg := action.DefaultRegistry()
	var (
		resolver engine.Resolver
		scripts  engine.ScriptRuntime
	)
	if policy.Restricted {
		reg = newRestrictedRegistry()
		if vErr := validateRestricted(wf, reg); vErr != nil {
			msg := fmt.Sprintf("restricted mode (ACTIONS_RESTRICTED): %v", vErr)
			fmt.Printf("  %s\n", msg)
			reportWorkflowResult(ctx, grpcClient, execID, 1, msg+"\n", 0)
			return nil
		}
	} else {
		resolver = newExecutorResolver(grpcClient)
		scripts = jsruntime.New()
	}

	// Open the live output stream. If it cannot be opened we still run the
	// workflow; output is then only persisted via the final ReportResult.
	stream, streamErr := grpcClient.StreamExecutionOutput(ctx)
	if streamErr != nil {
		fmt.Printf("  Warning: live output stream unavailable (%v); running without streaming\n", streamErr)
		stream = nil
	}

	var sendMu sync.Mutex
	emit := func(streamName string, b []byte) {
		if len(b) == 0 {
			return
		}
		os.Stdout.Write(b) // echo locally
		if stream == nil {
			return
		}
		sendMu.Lock()
		defer sendMu.Unlock()
		_ = stream.Send(&executorV1.ExecutionOutputChunk{
			ExecutionId: execID,
			Stream:      streamName,
			Data:        b,
		})
	}

	// Render the engine's events GitHub-Actions style: a header per step, the
	// step's output, then a result marker (✓/✗/⊘).
	sink := func(ev engine.OutputEvent) {
		switch ev.Kind {
		case engine.KindStepStarted:
			emit("stdout", []byte("\n▸ "+stepName(ev)+"\n"))
		case engine.KindStepFinished:
			emit("stdout", []byte(stepResultLine(ev)))
		default:
			emit(ev.Stream.String(), ev.Data)
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runner := engine.New(engine.Options{
		System:        system.NewReal(),
		Registry:      reg,
		Resolver:      resolver,
		ScriptRuntime: scripts,
		Output:        sink,
	})

	start := time.Now()
	result, runErr := runner.Run(runCtx, wf, command.GetInputs())
	duration := time.Since(start).Milliseconds()

	exitCode := int32(0)
	switch {
	case runErr != nil:
		exitCode = 1
		emit("stderr", []byte(fmt.Sprintf("\n✗ workflow failed: %v (%dms)\n", runErr, duration)))
	case result == nil || !result.Success:
		exitCode = 1
		emit("stderr", []byte(fmt.Sprintf("\n✗ workflow failed (%dms)\n", duration)))
	default:
		emit("stdout", []byte(fmt.Sprintf("\n✓ workflow succeeded (%dms)\n", duration)))
	}

	if stream != nil {
		if _, cErr := stream.CloseAndRecv(); cErr != nil {
			fmt.Printf("  Warning: closing output stream: %v\n", cErr)
		}
	}

	// Output already streamed and persisted; send empty output to preserve it.
	reportWorkflowResult(ctx, grpcClient, execID, exitCode, "", duration)
	return nil
}

// stepName is the display label for a step event (name, else id, else "step").
func stepName(ev engine.OutputEvent) string {
	if ev.Name != "" {
		return ev.Name
	}
	if ev.Step != "" {
		return ev.Step
	}
	return "step"
}

// stepResultLine renders a step's outcome marker, GitHub-Actions style.
func stepResultLine(ev engine.OutputEvent) string {
	switch ev.Outcome {
	case "success":
		return "✓ " + stepName(ev) + "\n"
	case "skipped":
		return "⊘ " + stepName(ev) + " (skipped)\n"
	default:
		return "✗ " + stepName(ev) + " (" + ev.Outcome + ")\n"
	}
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
