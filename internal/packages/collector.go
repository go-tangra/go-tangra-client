package packages

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Manager handles package information collection across different package managers
type Manager struct {
	aptManager    *APTManager
	dnfManager    *DNFManager
	apkManager    *APKManager
	pacmanManager *PacmanManager
}

// New creates a new package manager
func New() *Manager {
	return &Manager{
		aptManager:    &APTManager{},
		dnfManager:    &DNFManager{},
		apkManager:    &APKManager{},
		pacmanManager: &PacmanManager{},
	}
}

// GetPackages detects the system's package manager and collects package data
func (m *Manager) GetPackages() ([]PackageInfo, string, error) {
	pm := m.detectPackageManager()

	switch pm {
	case "apt":
		pkgs := m.aptManager.GetPackages()
		return pkgs, "apt", nil
	case "dnf", "yum":
		pkgs := m.dnfManager.GetPackages()
		return pkgs, pm, nil
	case "apk":
		pkgs := m.apkManager.GetPackages()
		return pkgs, "apk", nil
	case "pacman":
		pkgs, err := m.pacmanManager.GetPackages()
		return pkgs, "pacman", err
	default:
		return nil, "", fmt.Errorf("unsupported package manager: %s", pm)
	}
}

// detectPackageManager detects which package manager is available
func (m *Manager) detectPackageManager() string {
	if runtime.GOOS != "linux" {
		return "unknown"
	}

	if _, err := exec.LookPath("apk"); err == nil {
		return "apk"
	}
	if _, err := exec.LookPath("apt"); err == nil {
		return "apt"
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		return "apt"
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return "dnf"
	}
	if _, err := exec.LookPath("yum"); err == nil {
		return "yum"
	}
	if _, err := exec.LookPath("pacman"); err == nil {
		return "pacman"
	}

	return "unknown"
}

// CombinePackageData merges installed and upgradable package lists, deduplicating by name.
// Descriptions from installed packages are carried over to upgradable entries.
func CombinePackageData(installedPackages map[string]PackageInfo, upgradablePackages []PackageInfo) []PackageInfo {
	packages := make([]PackageInfo, 0, len(installedPackages))
	upgradableMap := make(map[string]bool)

	for _, pkg := range upgradablePackages {
		// Merge description from installed data if the upgradable entry lacks one
		if pkg.Description == "" {
			if installed, ok := installedPackages[pkg.Name]; ok {
				pkg.Description = installed.Description
			}
		}
		packages = append(packages, pkg)
		upgradableMap[pkg.Name] = true
	}

	for name, pkg := range installedPackages {
		if !upgradableMap[name] {
			packages = append(packages, pkg)
		}
	}

	return packages
}

// stripArchSuffix removes architecture suffix from RPM-style package names (e.g., "glibc.x86_64" -> "glibc")
func stripArchSuffix(name string) string {
	if idx := strings.LastIndex(name, "."); idx > 0 {
		archSuffix := name[idx+1:]
		if archSuffix == "x86_64" || archSuffix == "i686" || archSuffix == "i386" ||
			archSuffix == "noarch" || archSuffix == "aarch64" || archSuffix == "arm64" {
			return name[:idx]
		}
	}
	return name
}

// extractBasePackageName strips architecture suffix and version from RPM-style package names
func extractBasePackageName(packageString string) string {
	baseName := packageString
	if idx := strings.LastIndex(packageString, "."); idx > 0 {
		archSuffix := packageString[idx+1:]
		if archSuffix == "x86_64" || archSuffix == "i686" || archSuffix == "i386" ||
			archSuffix == "noarch" || archSuffix == "aarch64" || archSuffix == "arm64" {
			baseName = packageString[:idx]
		}
	}

	for i := 0; i < len(baseName); i++ {
		if baseName[i] == '-' && i+1 < len(baseName) {
			if baseName[i+1] >= '0' && baseName[i+1] <= '9' {
				return baseName[:i]
			}
		}
	}

	return baseName
}
