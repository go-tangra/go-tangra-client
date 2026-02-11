package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	scripts "github.com/tx7do/go-scripts"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
)

var (
	luaPool  *scripts.AutoGrowEnginePool
	jsPool   *scripts.AutoGrowEnginePool
	poolOnce sync.Once
)

func initEnginePools() {
	var err error
	luaPool, err = scripts.NewAutoGrowEnginePool(1, 3, scripts.LuaType)
	if err != nil {
		luaPool = nil
	}
	jsPool, err = scripts.NewAutoGrowEnginePool(1, 3, scripts.JavaScriptType)
	if err != nil {
		jsPool = nil
	}
}

func getLuaPool() (*scripts.AutoGrowEnginePool, error) {
	poolOnce.Do(initEnginePools)
	if luaPool == nil {
		return nil, fmt.Errorf("failed to initialize Lua engine pool")
	}
	return luaPool, nil
}

func getJSPool() (*scripts.AutoGrowEnginePool, error) {
	poolOnce.Do(initEnginePools)
	if jsPool == nil {
		return nil, fmt.Errorf("failed to initialize JavaScript engine pool")
	}
	return jsPool, nil
}

// CloseEnginePools releases embedded script engine resources. Call on shutdown.
func CloseEnginePools() {
	if luaPool != nil {
		luaPool.Close()
	}
	if jsPool != nil {
		jsPool.Close()
	}
}

// wrapJSConsole prepends a console shim so console.log/error/warn calls are captured.
func wrapJSConsole(content string) string {
	return `var console = { log: console_log, error: console_error, warn: console_error, info: console_log };
` + content
}

// wrapLuaPrint prepends an io table override so io.write calls are captured.
func wrapLuaPrint(content string) string {
	return `io = { write = io_write }
` + content
}

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

	switch scriptType {
	case executorV1.ScriptType_SCRIPT_TYPE_BASH:
		return executeBash(execCtx, content)
	case executorV1.ScriptType_SCRIPT_TYPE_JAVASCRIPT:
		return executeJS(execCtx, content)
	case executorV1.ScriptType_SCRIPT_TYPE_LUA:
		return executeLua(execCtx, content)
	default:
		return -1, "", "", fmt.Errorf("unsupported script type: %v", scriptType)
	}
}

func executeBash(ctx context.Context, content string) (int32, string, string, error) {
	tmpFile, err := os.CreateTemp("", "tangra-script-*.sh")
	if err != nil {
		return -1, "", "", fmt.Errorf("failed to create temp script file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		return -1, "", "", fmt.Errorf("failed to write temp script file: %w", err)
	}
	tmpFile.Close()

	cmd := exec.CommandContext(ctx, "bash", tmpFile.Name())

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

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

func executeJS(ctx context.Context, content string) (int32, string, string, error) {
	pool, err := getJSPool()
	if err != nil {
		return -1, "", "", err
	}

	var stdout, stderr strings.Builder

	_ = pool.RegisterFunction("print", func(args ...any) {
		fmt.Fprintln(&stdout, args...)
	})
	_ = pool.RegisterFunction("console_log", func(args ...any) {
		fmt.Fprintln(&stdout, args...)
	})
	_ = pool.RegisterFunction("console_error", func(args ...any) {
		fmt.Fprintln(&stderr, args...)
	})

	_, err = pool.ExecuteString(ctx, wrapJSConsole(content))
	if err != nil {
		return 1, stdout.String(), stderr.String(), nil
	}

	return 0, stdout.String(), stderr.String(), nil
}

func executeLua(ctx context.Context, content string) (int32, string, string, error) {
	pool, err := getLuaPool()
	if err != nil {
		return -1, "", "", err
	}

	var stdout, stderr strings.Builder

	_ = pool.RegisterFunction("print", func(args ...any) {
		fmt.Fprintln(&stdout, args...)
	})
	_ = pool.RegisterFunction("io_write", func(s string) {
		stdout.WriteString(s)
	})

	_, err = pool.ExecuteString(ctx, wrapLuaPrint(content))
	if err != nil {
		return 1, stdout.String(), stderr.String(), nil
	}

	return 0, stdout.String(), stderr.String(), nil
}
