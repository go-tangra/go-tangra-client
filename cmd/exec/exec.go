package exec

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/executor"
	"github.com/go-tangra/go-tangra-client/pkg/client"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
)

var (
	timeout  time.Duration
	noPrompt bool
)

// Command is the exec command
var Command = &cobra.Command{
	Use:   "exec <script_id>",
	Short: "Fetch and execute a script from the executor service",
	Long: `Fetch a script by ID from the executor service, verify its content hash,
and execute it locally. On first run, you'll be prompted to approve the script.
Subsequent runs will auto-execute if the hash hasn't changed.

Example:
  tangra-client exec abc123-def456
  tangra-client exec abc123-def456 --timeout 10m
  tangra-client exec abc123-def456 --no-prompt
`,
	Args: cobra.ExactArgs(1),
	RunE: runExec,
}

func init() {
	Command.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Execution timeout")
	Command.Flags().BoolVar(&noPrompt, "no-prompt", false, "Auto-reject if hash not approved (daemon behavior)")
}

func runExec(c *cobra.Command, args []string) error {
	scriptID := args[0]
	ctx := context.Background()

	executorServerAddr := cmd.GetExecutorServerAddr()
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	caFile := viper.GetString("ca")
	configDir := cmd.GetConfigDir()

	// Connect to executor service
	conn, err := client.CreateMTLSConnection(executorServerAddr, certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to connect to executor service at %s: %w", executorServerAddr, err)
	}
	defer conn.Close()

	grpcClient := executorV1.NewExecutorClientServiceClient(conn)

	// Initialize hash store
	hashStore := executor.NewHashStore(configDir)
	if err := hashStore.Load(); err != nil {
		return fmt.Errorf("failed to load hash store: %w", err)
	}

	// Prompt function
	promptFn := func(scriptName, oldHash, newHash string) bool {
		if noPrompt {
			fmt.Printf("Script %q hash not approved (--no-prompt), rejecting\n", scriptName)
			return false
		}

		if oldHash == "" {
			fmt.Printf("New script: %s\n", scriptName)
			fmt.Printf("  Content hash: %s\n", newHash)
			fmt.Print("  Approve and execute? [y/n]: ")
		} else {
			fmt.Printf("Script updated: %s\n", scriptName)
			fmt.Printf("  Old hash: %s\n", oldHash)
			fmt.Printf("  New hash: %s\n", newHash)
			fmt.Print("  Approve new version? [y/n]: ")
		}

		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		return answer == "y" || answer == "yes"
	}

	// Execute and measure duration
	startTime := time.Now()
	exitCode, stdout, stderr, err := executor.FetchAndExecute(
		ctx, grpcClient, scriptID, hashStore, promptFn, timeout,
	)
	durationMs := time.Since(startTime).Milliseconds()

	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	// Report execution result to server
	_, submitErr := grpcClient.SubmitExecution(ctx, &executorV1.SubmitExecutionRequest{
		ScriptId:    scriptID,
		ExitCode:    exitCode,
		Output:      stdout,
		ErrorOutput: stderr,
		DurationMs:  durationMs,
	})
	if submitErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to report execution result: %v\n", submitErr)
	}

	// Print output
	if stdout != "" {
		fmt.Print(stdout)
	}
	if stderr != "" {
		fmt.Fprintf(os.Stderr, "%s", stderr)
	}

	if exitCode != 0 {
		return fmt.Errorf("script exited with code %d", exitCode)
	}

	return nil
}
