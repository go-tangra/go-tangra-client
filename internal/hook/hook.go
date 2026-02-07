package hook

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	scripts "github.com/tx7do/go-scripts"
)

// HookType represents different types of hooks
type HookType string

const (
	HookDeploy      HookType = "deploy"
	HookPreRenewal  HookType = "pre-renewal"
	HookPostRenewal HookType = "post-renewal"
)

// ScriptType represents the type of script
type ScriptType string

const (
	ScriptTypeBash       ScriptType = "bash"
	ScriptTypeLua        ScriptType = "lua"
	ScriptTypeJavaScript ScriptType = "javascript"
)

// HookConfig contains configuration for hook execution
type HookConfig struct {
	BashScript  string
	ScriptFile  string
	ScriptType  ScriptType
	WorkDir     string
	Timeout     time.Duration
	Environment map[string]string
}

// HookContext contains information passed to hooks
type HookContext struct {
	CertName      string
	CertPath      string
	KeyPath       string
	ChainPath     string
	FullChainPath string
	CommonName    string
	DNSNames      []string
	IPAddresses   []string
	SerialNumber  string
	ExpiresAt     string
	IsRenewal     bool
}

// HookResult contains the result of a hook execution
type HookResult struct {
	Success  bool
	Output   string
	ErrorMsg string
	Duration time.Duration
	ExitCode int
}

// Runner executes hooks
type Runner struct {
	defaultTimeout time.Duration
	luaPool        *scripts.AutoGrowEnginePool
	jsPool         *scripts.AutoGrowEnginePool
}

// NewRunner creates a new hook runner
func NewRunner() *Runner {
	return &Runner{
		defaultTimeout: 5 * time.Minute,
	}
}

// Close releases resources
func (r *Runner) Close() {
	if r.luaPool != nil {
		r.luaPool.Close()
	}
	if r.jsPool != nil {
		r.jsPool.Close()
	}
}

// Run executes a hook with the given configuration and context
func (r *Runner) Run(ctx context.Context, hookType HookType, config *HookConfig, hookCtx *HookContext) *HookResult {
	if config == nil {
		return &HookResult{Success: true, Output: "No hook configured"}
	}

	if config.BashScript != "" {
		return r.runBashScript(ctx, hookType, config, hookCtx)
	}

	if config.ScriptFile != "" {
		return r.runScriptEngine(ctx, hookType, config, hookCtx)
	}

	return &HookResult{Success: true, Output: "No hook configured"}
}

func (r *Runner) runBashScript(ctx context.Context, hookType HookType, config *HookConfig, hookCtx *HookContext) *HookResult {
	start := time.Now()
	result := &HookResult{}

	scriptPath := config.BashScript
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("bash script not found: %s", scriptPath)
		return result
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = r.defaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "bash", scriptPath)

	if config.WorkDir != "" {
		cmd.Dir = config.WorkDir
	} else {
		cmd.Dir = filepath.Dir(scriptPath)
	}

	env := os.Environ()
	env = append(env, r.buildEnvVars(hookType, hookCtx)...)
	for k, v := range config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.Duration = time.Since(start)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Success = false
		result.ErrorMsg = err.Error()
		result.Output = combineOutput(stdout.String(), stderr.String())
	} else {
		result.Success = true
		result.ExitCode = 0
		result.Output = combineOutput(stdout.String(), stderr.String())
	}

	return result
}

func (r *Runner) runScriptEngine(ctx context.Context, hookType HookType, config *HookConfig, hookCtx *HookContext) *HookResult {
	start := time.Now()
	result := &HookResult{}

	scriptType := config.ScriptType
	if scriptType == "" {
		ext := strings.ToLower(filepath.Ext(config.ScriptFile))
		switch ext {
		case ".lua":
			scriptType = ScriptTypeLua
		case ".js":
			scriptType = ScriptTypeJavaScript
		default:
			result.Success = false
			result.ErrorMsg = fmt.Sprintf("unknown script type for extension: %s", ext)
			return result
		}
	}

	pool, err := r.getEnginePool(scriptType)
	if err != nil {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("failed to initialize script engine: %v", err)
		return result
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = r.defaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r.registerHookContext(pool, hookType, hookCtx)

	_, err = pool.ExecuteFile(execCtx, config.ScriptFile)
	result.Duration = time.Since(start)

	if err != nil {
		result.Success = false
		result.ErrorMsg = err.Error()
	} else {
		result.Success = true
	}

	return result
}

func (r *Runner) getEnginePool(scriptType ScriptType) (*scripts.AutoGrowEnginePool, error) {
	switch scriptType {
	case ScriptTypeLua:
		if r.luaPool == nil {
			pool, err := scripts.NewAutoGrowEnginePool(1, 5, scripts.LuaType)
			if err != nil {
				return nil, err
			}
			r.luaPool = pool
		}
		return r.luaPool, nil
	case ScriptTypeJavaScript:
		if r.jsPool == nil {
			pool, err := scripts.NewAutoGrowEnginePool(1, 5, scripts.JavaScriptType)
			if err != nil {
				return nil, err
			}
			r.jsPool = pool
		}
		return r.jsPool, nil
	default:
		return nil, fmt.Errorf("unsupported script type: %s", scriptType)
	}
}

func (r *Runner) registerHookContext(pool *scripts.AutoGrowEnginePool, hookType HookType, hookCtx *HookContext) {
	_ = pool.RegisterGlobal("LCM_HOOK_TYPE", string(hookType))

	if hookCtx != nil {
		_ = pool.RegisterGlobal("LCM_CERT_NAME", hookCtx.CertName)
		_ = pool.RegisterGlobal("LCM_CERT_PATH", hookCtx.CertPath)
		_ = pool.RegisterGlobal("LCM_KEY_PATH", hookCtx.KeyPath)
		_ = pool.RegisterGlobal("LCM_CHAIN_PATH", hookCtx.ChainPath)
		_ = pool.RegisterGlobal("LCM_FULLCHAIN_PATH", hookCtx.FullChainPath)
		_ = pool.RegisterGlobal("LCM_COMMON_NAME", hookCtx.CommonName)
		_ = pool.RegisterGlobal("LCM_DNS_NAMES", strings.Join(hookCtx.DNSNames, ","))
		_ = pool.RegisterGlobal("LCM_IP_ADDRESSES", strings.Join(hookCtx.IPAddresses, ","))
		_ = pool.RegisterGlobal("LCM_SERIAL_NUMBER", hookCtx.SerialNumber)
		_ = pool.RegisterGlobal("LCM_EXPIRES_AT", hookCtx.ExpiresAt)
		_ = pool.RegisterGlobal("LCM_IS_RENEWAL", hookCtx.IsRenewal)

		_ = pool.RegisterGlobal("LCM_CONTEXT", map[string]interface{}{
			"hookType":      string(hookType),
			"certName":      hookCtx.CertName,
			"certPath":      hookCtx.CertPath,
			"keyPath":       hookCtx.KeyPath,
			"chainPath":     hookCtx.ChainPath,
			"fullChainPath": hookCtx.FullChainPath,
			"commonName":    hookCtx.CommonName,
			"dnsNames":      hookCtx.DNSNames,
			"ipAddresses":   hookCtx.IPAddresses,
			"serialNumber":  hookCtx.SerialNumber,
			"expiresAt":     hookCtx.ExpiresAt,
			"isRenewal":     hookCtx.IsRenewal,
		})
	}

	_ = pool.RegisterFunction("exec", func(command string) (string, error) {
		cmd := exec.Command("sh", "-c", command)
		output, err := cmd.CombinedOutput()
		return string(output), err
	})

	_ = pool.RegisterFunction("readFile", func(path string) (string, error) {
		data, err := os.ReadFile(path)
		return string(data), err
	})

	_ = pool.RegisterFunction("writeFile", func(path, content string) error {
		return os.WriteFile(path, []byte(content), 0644)
	})

	_ = pool.RegisterFunction("fileExists", func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	})

	_ = pool.RegisterFunction("getEnv", func(key string) string {
		return os.Getenv(key)
	})

	_ = pool.RegisterFunction("log", func(msg string) {
		fmt.Println(msg)
	})
}

func (r *Runner) buildEnvVars(hookType HookType, hookCtx *HookContext) []string {
	env := []string{
		fmt.Sprintf("LCM_HOOK_TYPE=%s", hookType),
	}

	if hookCtx != nil {
		env = append(env,
			fmt.Sprintf("LCM_CERT_NAME=%s", hookCtx.CertName),
			fmt.Sprintf("LCM_CERT_PATH=%s", hookCtx.CertPath),
			fmt.Sprintf("LCM_KEY_PATH=%s", hookCtx.KeyPath),
			fmt.Sprintf("LCM_CHAIN_PATH=%s", hookCtx.ChainPath),
			fmt.Sprintf("LCM_FULLCHAIN_PATH=%s", hookCtx.FullChainPath),
			fmt.Sprintf("LCM_COMMON_NAME=%s", hookCtx.CommonName),
			fmt.Sprintf("LCM_DNS_NAMES=%s", strings.Join(hookCtx.DNSNames, ",")),
			fmt.Sprintf("LCM_IP_ADDRESSES=%s", strings.Join(hookCtx.IPAddresses, ",")),
			fmt.Sprintf("LCM_SERIAL_NUMBER=%s", hookCtx.SerialNumber),
			fmt.Sprintf("LCM_EXPIRES_AT=%s", hookCtx.ExpiresAt),
		)
		if hookCtx.IsRenewal {
			env = append(env, "LCM_IS_RENEWAL=true")
		} else {
			env = append(env, "LCM_IS_RENEWAL=false")
		}
	}

	return env
}

// RunDeployHook is a convenience method for running deploy hooks
func (r *Runner) RunDeployHook(ctx context.Context, config *HookConfig, hookCtx *HookContext) *HookResult {
	return r.Run(ctx, HookDeploy, config, hookCtx)
}

func combineOutput(stdout, stderr string) string {
	stdout = strings.TrimSpace(stdout)
	stderr = strings.TrimSpace(stderr)

	if stdout == "" && stderr == "" {
		return ""
	}
	if stdout == "" {
		return stderr
	}
	if stderr == "" {
		return stdout
	}
	return fmt.Sprintf("stdout:\n%s\nstderr:\n%s", stdout, stderr)
}
