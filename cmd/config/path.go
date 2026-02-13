package config

import (
	"fmt"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/spf13/cobra"
)

var pathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show the active config file path",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Println(cmd.GetConfigFilePath())
		return nil
	},
}
