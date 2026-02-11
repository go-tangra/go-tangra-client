package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/go-tangra/go-tangra-client/internal/machine"
)

var (
	serverAddr         string
	ipamServerAddr     string
	executorServerAddr string
	clientID           string
	tenantID           uint32
	certFile           string
	keyFile            string
	caFile             string
	configDir          string
	configFile         string
)

var rootCmd = &cobra.Command{
	Use:   "tangra-client",
	Short: "Tangra Client - Unified IPAM and LCM client agent",
	Long: `Tangra Client is a unified agent that runs on Linux hosts to:
  - IPAM: Auto-register and keep device info in sync (hostname, IPs, CPU, memory, disks, MACs)
  - LCM: Request certificates and automatically install renewals via streaming updates

Both functionalities share a single mTLS identity obtained during LCM registration.

Example workflow:
  1. Register:  tangra-client register --secret <shared-secret>
  2. Sync:      tangra-client sync --tenant-id 1
  3. Status:    tangra-client status
  4. Daemon:    tangra-client daemon --tenant-id 1
`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func GetRootCmd() *cobra.Command {
	return rootCmd
}

func GetServerAddr() string {
	return viper.GetString("server")
}

func GetIPAMServerAddr() string {
	return viper.GetString("ipam-server")
}

func GetExecutorServerAddr() string {
	return viper.GetString("executor-server")
}

func GetClientID() string {
	id := viper.GetString("client-id")
	if id == "" {
		id = machine.GetClientID()
	}
	return id
}

func GetTenantID() uint32 {
	return viper.GetUint32("tenant-id")
}

func GetConfigDir() string {
	dir := viper.GetString("config-dir")
	expanded, err := expandPath(dir)
	if err != nil {
		return dir
	}
	return expanded
}

func GetCertFile() string {
	return viper.GetString("cert")
}

func GetKeyFile() string {
	return viper.GetString("key")
}

func GetCAFile() string {
	return viper.GetString("ca")
}

func EnsureConfigDir() error {
	dir := GetConfigDir()
	return os.MkdirAll(dir, 0755)
}

func init() {
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "localhost:9100", "LCM server address")
	rootCmd.PersistentFlags().StringVar(&ipamServerAddr, "ipam-server", "localhost:9400", "IPAM server address")
	rootCmd.PersistentFlags().StringVar(&executorServerAddr, "executor-server", "localhost:9800", "Executor server address")
	rootCmd.PersistentFlags().StringVar(&clientID, "client-id", "", "Client ID (auto-generated from machine ID if empty)")
	rootCmd.PersistentFlags().Uint32Var(&tenantID, "tenant-id", 0, "IPAM tenant ID")
	rootCmd.PersistentFlags().StringVar(&certFile, "cert", "", "Client certificate file path")
	rootCmd.PersistentFlags().StringVar(&keyFile, "key", "", "Client private key file path")
	rootCmd.PersistentFlags().StringVar(&caFile, "ca", "", "CA certificate file path")
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "~/.tangra-client", "Configuration directory")
	rootCmd.PersistentFlags().StringVar(&configFile, "config-file", "", "Configuration file path")

	_ = viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
	_ = viper.BindPFlag("ipam-server", rootCmd.PersistentFlags().Lookup("ipam-server"))
	_ = viper.BindPFlag("executor-server", rootCmd.PersistentFlags().Lookup("executor-server"))
	_ = viper.BindPFlag("client-id", rootCmd.PersistentFlags().Lookup("client-id"))
	_ = viper.BindPFlag("tenant-id", rootCmd.PersistentFlags().Lookup("tenant-id"))
	_ = viper.BindPFlag("cert", rootCmd.PersistentFlags().Lookup("cert"))
	_ = viper.BindPFlag("key", rootCmd.PersistentFlags().Lookup("key"))
	_ = viper.BindPFlag("ca", rootCmd.PersistentFlags().Lookup("ca"))
	_ = viper.BindPFlag("config-dir", rootCmd.PersistentFlags().Lookup("config-dir"))
}

func initConfig() error {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		dir := GetConfigDir()
		viper.AddConfigPath(dir)
		viper.AddConfigPath("/etc/tangra-client")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	_ = viper.ReadInConfig()

	clientID := GetClientID()
	configDir := GetConfigDir()

	if viper.GetString("cert") == "" {
		viper.Set("cert", filepath.Join(configDir, fmt.Sprintf("%s.crt", clientID)))
	}
	if viper.GetString("key") == "" {
		viper.Set("key", filepath.Join(configDir, fmt.Sprintf("%s.key", clientID)))
	}
	if viper.GetString("ca") == "" {
		viper.Set("ca", filepath.Join(configDir, "ca.crt"))
	}

	return nil
}

// BuildInfo holds version information injected at build time.
type BuildInfo struct {
	Version    string
	CommitHash string
	BuildDate  string
}

var buildInfo BuildInfo

// SetBuildInfo sets the build information (called from main).
func SetBuildInfo(version, commitHash, buildDate string) {
	buildInfo = BuildInfo{
		Version:    version,
		CommitHash: commitHash,
		BuildDate:  buildDate,
	}
}

// GetBuildInfo returns the current build information.
func GetBuildInfo() BuildInfo {
	return buildInfo
}

func expandPath(path string) (string, error) {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	} else if path == "~" {
		return os.UserHomeDir()
	}
	return path, nil
}
