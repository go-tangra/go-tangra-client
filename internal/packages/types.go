package packages

// PackageInfo represents an installed or upgradable package
type PackageInfo struct {
	Name             string
	Description      string
	CurrentVersion   string
	AvailableVersion string
	NeedsUpdate      bool
	IsSecurityUpdate bool
}
