package main

import (
	"fmt"
	"os"

	"github.com/go-tangra/go-tangra-client/cmd"
	certCmd "github.com/go-tangra/go-tangra-client/cmd/cert"
	"github.com/go-tangra/go-tangra-client/cmd/daemon"
	execCmd "github.com/go-tangra/go-tangra-client/cmd/exec"
	"github.com/go-tangra/go-tangra-client/cmd/register"
	"github.com/go-tangra/go-tangra-client/cmd/status"
	"github.com/go-tangra/go-tangra-client/cmd/sync"
	"github.com/go-tangra/go-tangra-client/cmd/update"
	"github.com/go-tangra/go-tangra-client/cmd/version"
)

var (
	buildVersion = "dev"
	commitHash   = "unknown"
	buildDate    = "unknown"
)

func main() {
	cmd.SetBuildInfo(buildVersion, commitHash, buildDate)

	rootCmd := cmd.GetRootCmd()
	rootCmd.AddCommand(register.Command)
	rootCmd.AddCommand(status.Command)
	rootCmd.AddCommand(sync.Command)
	rootCmd.AddCommand(daemon.Command)
	rootCmd.AddCommand(execCmd.Command)
	rootCmd.AddCommand(version.Command)
	rootCmd.AddCommand(update.Command)
	rootCmd.AddCommand(certCmd.Command)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
