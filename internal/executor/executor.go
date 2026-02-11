package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
)

// FetchAndExecute fetches a script from the executor service, checks the hash,
// and executes it if approved. Returns exit code, stdout, stderr, and error.
func FetchAndExecute(
	ctx context.Context,
	grpcClient executorV1.ExecutorClientServiceClient,
	scriptID string,
	hashStore *HashStore,
	promptFn func(scriptName, oldHash, newHash string) bool,
	timeout time.Duration,
) (int32, string, string, error) {
	// Fetch script
	resp, err := grpcClient.FetchScript(ctx, &executorV1.FetchScriptRequest{
		ScriptId: scriptID,
	})
	if err != nil {
		return -1, "", "", fmt.Errorf("failed to fetch script: %w", err)
	}

	scriptName := resp.GetScriptName()
	content := resp.GetContent()
	contentHash := resp.GetContentHash()
	scriptType := resp.GetScriptType()

	// Check hash approval
	oldHash := hashStore.GetHash(scriptID)
	if oldHash == "" {
		// First run — need approval
		if promptFn != nil && !promptFn(scriptName, "", contentHash) {
			return -1, "", "", fmt.Errorf("script %s not approved", scriptName)
		}
	} else if oldHash != contentHash {
		// Hash changed — need re-approval
		if promptFn != nil && !promptFn(scriptName, oldHash, contentHash) {
			return -1, "", "", fmt.Errorf("script %s hash changed, not approved", scriptName)
		}
	}
	// Hash matches (or just approved) — execute

	// Save approved hash
	if err := hashStore.Approve(scriptID, contentHash); err != nil {
		fmt.Printf("Warning: failed to save approved hash: %v\n", err)
	}

	// Execute script
	return executeScript(ctx, scriptType, content, timeout)
}

// executeScript runs the script content using the appropriate interpreter.
func executeScript(ctx context.Context, scriptType executorV1.ScriptType, content string, timeout time.Duration) (int32, string, string, error) {
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd

	switch scriptType {
	case executorV1.ScriptType_SCRIPT_TYPE_BASH:
		cmd = exec.CommandContext(execCtx, "bash", "-c", content)
	case executorV1.ScriptType_SCRIPT_TYPE_JAVASCRIPT:
		cmd = exec.CommandContext(execCtx, "node", "-e", content)
	case executorV1.ScriptType_SCRIPT_TYPE_LUA:
		cmd = exec.CommandContext(execCtx, "lua", "-e", content)
	default:
		return -1, "", "", fmt.Errorf("unsupported script type: %v", scriptType)
	}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := int32(0)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = int32(exitErr.ExitCode())
		} else {
			return -1, stdout.String(), stderr.String(), fmt.Errorf("execution failed: %w", err)
		}
	}

	return exitCode, stdout.String(), stderr.String(), nil
}
