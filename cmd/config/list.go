package config

import (
	"fmt"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all config values",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		for _, key := range cmd.ValidConfigKeys {
			val := viper.GetString(key)
			if val == "" {
				fmt.Printf("%s: (not set)\n", key)
			} else {
				fmt.Printf("%s: %s\n", key, val)
			}
		}
		return nil
	},
}
