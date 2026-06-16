package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/go-tangra/go-tangra-client/cmd"
	"github.com/go-tangra/go-tangra-client/internal/hook"
	"github.com/go-tangra/go-tangra-client/internal/lcm"
	"github.com/go-tangra/go-tangra-client/internal/nginx"
	"github.com/go-tangra/go-tangra-client/internal/registration"
	"github.com/go-tangra/go-tangra-client/internal/storage"
	"github.com/go-tangra/go-tangra-client/pkg/backoff"
	"github.com/go-tangra/go-tangra-client/pkg/client"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
	ipampb "github.com/go-tangra/go-tangra-ipam/gen/go/ipam/service/v1"
	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"

	executorint "github.com/go-tangra/go-tangra-client/internal/executor"
	ipamint "github.com/go-tangra/go-tangra-client/internal/ipam"
)

var (
	deployHook       string
	deployScriptHook string
	hookTimeout      time.Duration
	syncInterval     time.Duration
	oneShot          bool
	disableIPAM      bool
	disableLCM       bool
	disableExecutor  bool
	registerSecret   string

	// Nginx SSL deploy options
	nginxHTTP2      bool
	nginxHSTS       bool
	nginxHSTSMaxAge int
	nginxOCSP       bool
	nginxProtocols  string
	nginxCiphers    string
	nginxDHParam    string
)

// Command is the daemon command
var Command = &cobra.Command{
	Use:   "daemon",
	Short: "Run the unified daemon (IPAM sync loop + LCM cert streaming)",
	Long: `Run the Tangra client in daemon mode.

In this mode, the client runs two parallel goroutines:
  1. LCM Streamer: Syncs certificates and listens for real-time updates
  2. IPAM Sync: Periodically syncs device information with the IPAM server

Both use the same mTLS identity obtained during registration.

The certificates are stored in a certbot-like structure:
  ~/.tangra-client/live/<cert-name>/cert.pem      - Certificate
  ~/.tangra-client/live/<cert-name>/privkey.pem   - Private key
  ~/.tangra-client/live/<cert-name>/chain.pem     - CA chain
  ~/.tangra-client/live/<cert-name>/fullchain.pem - Cert + chain

Example:
  tangra-client daemon --tenant-id 1
  tangra-client daemon --tenant-id 1 --deploy-hook /usr/local/bin/reload-nginx.sh
  tangra-client daemon --one-shot
  tangra-client daemon --disable-ipam  # LCM only
  tangra-client daemon --disable-lcm   # IPAM only
`,
	RunE: runDaemon,
}

func init() {
	Command.Flags().StringVar(&deployHook, "deploy-hook", "", "Path to bash script to run after certificate deployment")
	Command.Flags().StringVar(&deployScriptHook, "deploy-script-hook", "", "Path to Lua (.lua) or JavaScript (.js) script for cert deployment")
	Command.Flags().DurationVar(&hookTimeout, "hook-timeout", 5*time.Minute, "Timeout for hook execution")
	Command.Flags().DurationVar(&syncInterval, "sync-interval", 1*time.Hour, "IPAM sync interval and LCM fallback interval")
	Command.Flags().BoolVar(&oneShot, "one-shot", false, "Run both syncs once and exit")
	Command.Flags().BoolVar(&disableIPAM, "disable-ipam", false, "Skip IPAM sync goroutine")
	Command.Flags().BoolVar(&disableLCM, "disable-lcm", false, "Skip LCM streaming goroutine")
	Command.Flags().BoolVar(&disableExecutor, "disable-executor", false, "Skip executor streaming goroutine")
	Command.Flags().StringVar(&registerSecret, "secret", "", "Shared secret for auto-registration when not yet registered")

	// Nginx SSL deploy options
	Command.Flags().BoolVar(&nginxHTTP2, "nginx-http2", true, "Enable HTTP/2 in nginx SSL config")
	Command.Flags().BoolVar(&nginxHSTS, "nginx-hsts", true, "Enable HSTS header in nginx SSL config")
	Command.Flags().IntVar(&nginxHSTSMaxAge, "nginx-hsts-max-age", 31536000, "HSTS max-age in seconds")
	Command.Flags().BoolVar(&nginxOCSP, "nginx-ocsp-stapling", true, "Enable OCSP stapling in nginx SSL config")
	Command.Flags().StringVar(&nginxProtocols, "nginx-ssl-protocols", "TLSv1.2 TLSv1.3", "SSL protocols for nginx")
	Command.Flags().StringVar(&nginxCiphers, "nginx-ssl-ciphers", "", "SSL cipher suite for nginx")
	Command.Flags().StringVar(&nginxDHParam, "nginx-dhparam", "", "Path to DH parameters file for nginx")

	// Bind daemon flags to viper so they can also be set via
	// /etc/tangra-client/config.yaml. With BindPFlag the CLI value
	// (when explicitly passed) wins over the config file, and the
	// config file wins over the flag's compile-time default — which
	// is the priority operators usually expect.
	_ = viper.BindPFlag("deploy-hook", Command.Flags().Lookup("deploy-hook"))
	_ = viper.BindPFlag("deploy-script-hook", Command.Flags().Lookup("deploy-script-hook"))
	_ = viper.BindPFlag("hook-timeout", Command.Flags().Lookup("hook-timeout"))
	_ = viper.BindPFlag("sync-interval", Command.Flags().Lookup("sync-interval"))
	_ = viper.BindPFlag("disable-ipam", Command.Flags().Lookup("disable-ipam"))
	_ = viper.BindPFlag("disable-lcm", Command.Flags().Lookup("disable-lcm"))
	_ = viper.BindPFlag("disable-executor", Command.Flags().Lookup("disable-executor"))
}

func runDaemon(c *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	clientID := cmd.GetClientID()
	tenantID := cmd.GetTenantID()
	serverAddr := cmd.GetServerAddr()
	ipamServerAddr := cmd.GetIPAMServerAddr()
	executorServerAddr := cmd.GetExecutorServerAddr()
	configDir := cmd.GetConfigDir()

	// Resolve daemon-scoped settings via viper so values declared in
	// /etc/tangra-client/config.yaml take effect even when no CLI flag
	// is passed (e.g. when running under systemd via ExecStart).
	// BindPFlag was set up in init(), so the precedence is:
	//   explicit CLI flag > config file > flag default.
	deployHook = viper.GetString("deploy-hook")
	deployScriptHook = viper.GetString("deploy-script-hook")
	hookTimeout = viper.GetDuration("hook-timeout")
	syncInterval = viper.GetDuration("sync-interval")
	disableIPAM = viper.GetBool("disable-ipam")
	disableLCM = viper.GetBool("disable-lcm")
	disableExecutor = viper.GetBool("disable-executor")

	// mTLS credentials
	certFile := viper.GetString("cert")
	if certFile == "" {
		certFile = filepath.Join(configDir, fmt.Sprintf("%s.crt", clientID))
	}
	keyFile := viper.GetString("key")
	if keyFile == "" {
		keyFile = filepath.Join(configDir, fmt.Sprintf("%s.key", clientID))
	}
	caFile := viper.GetString("ca")
	if caFile == "" {
		caFile = filepath.Join(configDir, "ca.crt")
	}

	// Pre-flight: check if mTLS credentials exist; auto-register if --secret is provided
	certsExist := fileExists(certFile) && fileExists(keyFile) && fileExists(caFile)
	if !certsExist {
		if registerSecret == "" {
			var missingFiles []string
			for _, f := range []struct{ name, path string }{
				{"certificate", certFile},
				{"private key", keyFile},
				{"CA certificate", caFile},
			} {
				if !fileExists(f.path) {
					missingFiles = append(missingFiles, fmt.Sprintf("  - %s: %s", f.name, f.path))
				}
			}
			return fmt.Errorf("client is not registered — missing mTLS credentials:\n%s\n\nRun 'tangra-client register' or start daemon with --secret flag to auto-register",
				strings.Join(missingFiles, "\n"))
		}

		// Auto-register
		fmt.Println("Credentials not found — auto-registering...")
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		regCtx, regCancel := context.WithTimeout(ctx, 30*time.Second)
		defer regCancel()

		_, err := registration.Register(regCtx, &registration.Config{
			ServerAddr: serverAddr,
			ClientID:   clientID,
			CertFile:   certFile,
			KeyFile:    keyFile,
			CAFile:     caFile,
			Secret:     registerSecret,
		})
		if err != nil {
			return fmt.Errorf("auto-registration failed: %w", err)
		}
		fmt.Println()
	}

	fmt.Printf("Tangra Client Daemon\n")
	fmt.Printf("  Client ID:    %s\n", clientID)
	fmt.Printf("  LCM Server:   %s\n", serverAddr)
	fmt.Printf("  IPAM Server:  %s\n", ipamServerAddr)
	fmt.Printf("  Executor:     %s\n", executorServerAddr)
	fmt.Printf("  Tenant ID:    %d\n", tenantID)
	fmt.Printf("  Config Dir:   %s\n", configDir)
	fmt.Printf("  Sync Interval: %s\n", syncInterval)
	if disableIPAM {
		fmt.Printf("  IPAM: DISABLED\n")
	}
	if disableLCM {
		fmt.Printf("  LCM: DISABLED\n")
	}
	if disableExecutor {
		fmt.Printf("  Executor: DISABLED\n")
	}
	if deployHook != "" {
		fmt.Printf("  Deploy Hook (bash): %s\n", deployHook)
	}
	if deployScriptHook != "" {
		fmt.Printf("  Deploy Hook (script): %s\n", deployScriptHook)
	}
	fmt.Println()

	// Initialize hook runner and cert store for LCM
	hookRunner := hook.NewRunner()
	defer hookRunner.Close()
	defer executorint.CloseEnginePools()

	hookConfig := &hook.HookConfig{
		BashScript: deployHook,
		ScriptFile: deployScriptHook,
		Timeout:    hookTimeout,
	}

	certStore, err := storage.NewCertStore(configDir)
	if err != nil {
		return fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	stateStore := storage.NewStateStore(configDir)

	// Discover nginx for automatic SSL deployment
	var nginxDeployer *nginx.Deployer
	nginxInfo, nginxErr := nginx.Discover()
	if nginxErr == nil {
		fmt.Printf("  Nginx:        %s (v%s)\n", nginxInfo.BinaryPath, nginxInfo.Version)
		nginxDeployer = nginx.NewDeployer(nginxInfo, &nginx.InstallOptions{
			HTTP2:        nginxHTTP2,
			HSTS:         nginxHSTS,
			HSTSMaxAge:   nginxHSTSMaxAge,
			OCSPStapling: nginxOCSP,
			SSLProtocols: nginxProtocols,
			SSLCiphers:   nginxCiphers,
			DHParamPath:  nginxDHParam,
		})
	} else {
		fmt.Printf("  Nginx:        not detected\n")
	}

	if oneShot {
		return runOneShot(ctx, clientID, tenantID, serverAddr, ipamServerAddr, certFile, keyFile, caFile, certStore, stateStore, hookRunner, hookConfig, nginxDeployer)
	}

	// Continuous daemon mode with errgroup
	g, gCtx := errgroup.WithContext(ctx)

	// LCM goroutine
	if !disableLCM {
		g.Go(func() error {
			return runWithReconnect(gCtx, "LCM", serverAddr, certFile, keyFile, caFile, func(ctx context.Context, addr, cf, kf, ca string) error {
				lcmConn, err := client.CreateMTLSConnection(addr, cf, kf, ca)
				if err != nil {
					return fmt.Errorf("failed to connect: %w", err)
				}
				defer lcmConn.Close()

				lcmClient := lcmV1.NewLcmClientServiceClient(lcmConn)
				jobClient := lcmV1.NewLcmCertificateJobServiceClient(lcmConn)

				// Initial sync — mTLS certificates
				fmt.Println("LCM: Syncing certificates...")
				updated, err := lcm.SyncCertificates(ctx, lcmClient, certStore, hookRunner, hookConfig, nginxDeployer)
				if err != nil {
					fmt.Printf("LCM: mTLS cert sync failed: %v\n", err)
				} else {
					fmt.Printf("LCM: mTLS sync complete: %d certificates updated\n", updated)
				}

				// Sync certificate jobs (ACME, etc.)
				fmt.Println("LCM: Syncing certificate jobs...")
				jobUpdated, err := lcm.SyncCertificateJobs(ctx, jobClient, certStore, hookRunner, hookConfig, nginxDeployer)
				if err != nil {
					fmt.Printf("LCM: Job sync failed: %v\n", err)
				} else {
					fmt.Printf("LCM: Job sync complete: %d certificates downloaded\n", jobUpdated)
				}

				// Start streaming
				fmt.Println("LCM: Listening for certificate updates...")
				return lcm.RunStreamer(ctx, lcmClient, certStore, hookRunner, hookConfig, nginxDeployer, syncInterval)
			})
		})
	}

	// IPAM goroutine
	if !disableIPAM {
		g.Go(func() error {
			return runWithReconnect(gCtx, "IPAM", ipamServerAddr, certFile, keyFile, caFile, func(ctx context.Context, addr, cf, kf, ca string) error {
				ipamConn, err := client.CreateMTLSConnection(addr, cf, kf, ca)
				if err != nil {
					return fmt.Errorf("failed to connect: %w", err)
				}
				defer ipamConn.Close()

				clients := &ipamint.IPAMClients{
					Device:        ipampb.NewDeviceServiceClient(ipamConn),
					Subnet:        ipampb.NewSubnetServiceClient(ipamConn),
					IpAddress:     ipampb.NewIpAddressServiceClient(ipamConn),
					DevicePackage: ipampb.NewDevicePackageServiceClient(ipamConn),
				}
				return ipamint.RunSyncLoop(ctx, clients, stateStore, tenantID, clientID, syncInterval)
			})
		})
	}

	// Executor goroutine
	if !disableExecutor {
		g.Go(func() error {
			err := runWithReconnect(gCtx, "Executor", executorServerAddr, certFile, keyFile, caFile, func(ctx context.Context, addr, cf, kf, ca string) error {
				executorConn, err := client.CreateMTLSConnection(addr, cf, kf, ca)
				if err != nil {
					return fmt.Errorf("failed to connect: %w", err)
				}
				defer executorConn.Close()

				executorClient := executorV1.NewExecutorClientServiceClient(executorConn)

				// Initialize hash store
				hashStore := executorint.NewHashStore(configDir)
				if err := hashStore.Load(); err != nil {
					return fmt.Errorf("failed to load hash store: %w", err)
				}

				return executorint.RunStreamer(ctx, executorClient, hashStore, clientID, cmd.GetBuildInfo().Version, 5*time.Minute, syncInterval)
			})
			// A self-update applied the new binary: restart NOW rather than
			// returning up to g.Wait(), which would block until the LCM/IPAM
			// goroutines also drain (up to a full sync interval). handleRestart
			// re-execs / exits and does not return.
			if errors.Is(err, executorint.ErrRestartRequested) {
				return handleRestart()
			}
			return err
		})
	}

	if err := g.Wait(); err != nil {
		if errors.Is(err, executorint.ErrRestartRequested) {
			return handleRestart()
		}
		return err
	}
	return nil
}

func runOneShot(ctx context.Context, clientID string, tenantID uint32, serverAddr, ipamServerAddr, certFile, keyFile, caFile string, certStore *storage.CertStore, stateStore *storage.StateStore, hookRunner *hook.Runner, hookConfig *hook.HookConfig, nginxDeployer *nginx.Deployer) error {
	fmt.Println("Running one-shot sync...")

	// LCM sync
	if !disableLCM {
		fmt.Println("\n--- LCM Certificate Sync ---")
		lcmConn, err := client.CreateMTLSConnection(serverAddr, certFile, keyFile, caFile)
		if err != nil {
			fmt.Printf("LCM: Failed to connect: %v\n", err)
		} else {
			defer lcmConn.Close()
			lcmClient := lcmV1.NewLcmClientServiceClient(lcmConn)
			updated, err := lcm.SyncCertificates(ctx, lcmClient, certStore, hookRunner, hookConfig, nginxDeployer)
			if err != nil {
				fmt.Printf("LCM: mTLS cert sync failed: %v\n", err)
			} else {
				fmt.Printf("LCM: %d mTLS certificates updated\n", updated)
			}

			jobClient := lcmV1.NewLcmCertificateJobServiceClient(lcmConn)
			jobUpdated, err := lcm.SyncCertificateJobs(ctx, jobClient, certStore, hookRunner, hookConfig, nginxDeployer)
			if err != nil {
				fmt.Printf("LCM: Job sync failed: %v\n", err)
			} else {
				fmt.Printf("LCM: %d job certificates downloaded\n", jobUpdated)
			}
		}
	}

	// IPAM sync
	if !disableIPAM {
		fmt.Println("\n--- IPAM Device Sync ---")
		ipamConn, err := client.CreateMTLSConnection(ipamServerAddr, certFile, keyFile, caFile)
		if err != nil {
			fmt.Printf("IPAM: Failed to connect: %v\n", err)
		} else {
			defer ipamConn.Close()
			clients := &ipamint.IPAMClients{
				Device:        ipampb.NewDeviceServiceClient(ipamConn),
				Subnet:        ipampb.NewSubnetServiceClient(ipamConn),
				IpAddress:     ipampb.NewIpAddressServiceClient(ipamConn),
				DevicePackage: ipampb.NewDevicePackageServiceClient(ipamConn),
			}
			changed, err := ipamint.SyncDevice(ctx, clients, stateStore, tenantID, clientID)
			if err != nil {
				fmt.Printf("IPAM: Sync failed: %v\n", err)
			} else if changed {
				fmt.Println("IPAM: Device synced with changes")
			} else {
				fmt.Println("IPAM: No changes detected")
			}
		}
	}

	fmt.Println("\nOne-shot sync complete.")
	return nil
}

// runWithReconnect wraps a service function with connection-level reconnect and exponential backoff.
// If the service function returns an error (connection lost, stream broken, etc.), a new connection
// is established after a backoff delay. The backoff resets on successful connection.
func runWithReconnect(ctx context.Context, name, serverAddr, certFile, keyFile, caFile string, fn func(ctx context.Context, addr, certFile, keyFile, caFile string) error) error {
	bo := backoff.New()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		fmt.Printf("%s: Connecting to %s...\n", name, serverAddr)
		err := fn(ctx, serverAddr, certFile, keyFile, caFile)
		if err != nil {
			if errors.Is(err, executorint.ErrRestartRequested) {
				return err
			}
			if ctx.Err() != nil {
				return nil
			}
			fmt.Printf("%s: Connection error: %v\n", name, err)
		}

		fmt.Printf("%s: ", name)
		if _, cancelled := bo.Wait(ctx); cancelled {
			return nil
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// handleRestart restarts the daemon after a successful binary update. It
// re-execs the current binary in place, which is immediate and independent of
// any service-manager Restart= policy. If re-exec fails it exits cleanly so a
// supervisor (systemd Restart=always) brings the daemon back on the new binary.
func handleRestart() error {
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Update applied but executable path unknown (%v); exiting for the service manager to restart\n", err)
		os.Exit(0)
	}
	fmt.Println("Update applied, re-executing the new binary...")
	if execErr := syscall.Exec(exe, os.Args, os.Environ()); execErr != nil {
		fmt.Printf("re-exec failed (%v); exiting for the service manager to restart\n", execErr)
		os.Exit(0)
	}
	return nil
}
