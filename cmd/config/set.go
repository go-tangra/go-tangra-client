package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var setCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a config value and persist to file",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		key := args[0]
		value := args[1]

		if !isValidKey(key) {
			return fmt.Errorf("unknown config key %q (valid keys: %s)", key, strings.Join(cmd.ValidConfigKeys, ", "))
		}

		// Type conversion for non-string keys.
		var typedValue interface{} = value
		if key == "tenant-id" {
			v, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid value for tenant-id: %w", err)
			}
			typedValue = uint32(v)
		}

		// Update viper in-memory.
		viper.Set(key, typedValue)

		// Read-modify-write the YAML config file.
		cfgPath := cmd.GetConfigFilePath()

		data := make(map[string]interface{})
		existing, err := os.ReadFile(cfgPath)
		if err == nil {
			_ = yaml.Unmarshal(existing, &data)
		}

		data[key] = typedValue

		out, err := yaml.Marshal(data)
		if err != nil {
			return fmt.Errorf("marshaling config: %w", err)
		}

		if err := cmd.EnsureConfigDir(); err != nil {
			return fmt.Errorf("creating config directory: %w", err)
		}

		if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
			return fmt.Errorf("creating config file directory: %w", err)
		}

		if err := os.WriteFile(cfgPath, out, 0600); err != nil {
			return fmt.Errorf("writing config file: %w", err)
		}

		fmt.Printf("%s: %v\n", key, typedValue)
		return nil
	},
}
