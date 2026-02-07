package main

import (
	"fmt"
	"os"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/cmd/daemon"
	"github.com/go-tangra/go-tangra-client/cmd/register"
	"github.com/go-tangra/go-tangra-client/cmd/status"
	"github.com/go-tangra/go-tangra-client/cmd/sync"
)

func main() {
	rootCmd := cmd.GetRootCmd()
	rootCmd.AddCommand(register.Command)
	rootCmd.AddCommand(status.Command)
	rootCmd.AddCommand(sync.Command)
	rootCmd.AddCommand(daemon.Command)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
