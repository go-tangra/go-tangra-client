package version

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/go-tangra/go-tangra-client/cmd"
)

// Command is the version command.
var Command = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		info := cmd.GetBuildInfo()
		fmt.Printf("tangra-client %s\n", info.Version)
		fmt.Printf("  Commit:    %s\n", info.CommitHash)
		fmt.Printf("  Built:     %s\n", info.BuildDate)
		fmt.Printf("  Go:        %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}
