package config

import (
	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/spf13/cobra"
)

// Command is the config command group.
var Command = &cobra.Command{
	Use:   "config",
	Short: "View and modify client configuration",
	Long: `View and modify tangra-client configuration values.

Subcommands:
  get    Get a single config value
  set    Set a config value and persist to file
  list   List all current config values
  path   Show the active config file path

Example:
  tangra-client config list
  tangra-client config get server
  tangra-client config set server lcm.example.com:9100
  tangra-client config path
`,
}

func init() {
	Command.AddCommand(getCmd)
	Command.AddCommand(setCmd)
	Command.AddCommand(listCmd)
	Command.AddCommand(pathCmd)
}

func isValidKey(key string) bool {
	for _, k := range cmd.ValidConfigKeys {
		if k == key {
			return true
		}
	}
	return false
}
