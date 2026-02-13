package config

import (
	"fmt"
	"strings"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var getCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a config value",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		key := args[0]
		if !isValidKey(key) {
			return fmt.Errorf("unknown config key %q (valid keys: %s)", key, strings.Join(cmd.ValidConfigKeys, ", "))
		}
		val := viper.GetString(key)
		if val == "" {
			fmt.Printf("%s: (not set)\n", key)
		} else {
			fmt.Printf("%s: %s\n", key, val)
		}
		return nil
	},
}
