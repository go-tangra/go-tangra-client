package packages

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// APKManager handles APK package information collection
type APKManager struct{}

// GetPackages gets package information for APK-based systems (Alpine Linux)
func (m *APKManager) GetPackages() []PackageInfo {
	// Update package index
	updateCmd := exec.Command("apk", "update", "-q")
	if err := updateCmd.Run(); err != nil {
		fmt.Printf("  packages: failed to update package index: %v\n", err)
	}

	// Get installed packages
	installedCmd := exec.Command("apk", "list", "--installed")
	installedOutput, err := installedCmd.Output()
	var installedPackages map[string]PackageInfo
	if err != nil {
		fmt.Printf("  packages: failed to get installed packages: %v\n", err)
		installedPackages = make(map[string]PackageInfo)
	} else {
		installedPackages = m.parseInstalledPackages(string(installedOutput))
	}

	// Get upgradable packages
	upgradableCmd := exec.Command("apk", "-u", "list")
	upgradableOutput, err := upgradableCmd.Output()
	var upgradablePackages []PackageInfo
	if err != nil {
		upgradablePackages = []PackageInfo{}
	} else {
		upgradablePackages = m.parseUpgradablePackages(string(upgradableOutput), installedPackages)
	}

	return CombinePackageData(installedPackages, upgradablePackages)
}

// parseInstalledPackages parses apk list --installed output
func (m *APKManager) parseInstalledPackages(output string) map[string]PackageInfo {
	installedPackages := make(map[string]PackageInfo)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, "[installed]") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		packageName, version := extractAPKPackageNameAndVersion(fields[0])
		if packageName == "" || version == "" {
			continue
		}

		installedPackages[packageName] = PackageInfo{
			Name:           packageName,
			CurrentVersion: version,
		}
	}

	return installedPackages
}

// parseUpgradablePackages parses apk -u list output
func (m *APKManager) parseUpgradablePackages(output string, installedPackages map[string]PackageInfo) []PackageInfo {
	var packages []PackageInfo

	upgradableFromRegex := regexp.MustCompile(`\[upgradable from: (.+)\]`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := upgradableFromRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		oldPackageWithVersion := matches[1]

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		newPackageName, newVersion := extractAPKPackageNameAndVersion(fields[0])
		_, oldVersion := extractAPKPackageNameAndVersion(oldPackageWithVersion)

		if newPackageName == "" || newVersion == "" {
			continue
		}

		currentVersion := oldVersion
		if installedPkg, found := installedPackages[newPackageName]; found {
			currentVersion = installedPkg.CurrentVersion
		}

		packages = append(packages, PackageInfo{
			Name:             newPackageName,
			CurrentVersion:   currentVersion,
			AvailableVersion: newVersion,
			NeedsUpdate:      true,
			IsSecurityUpdate: false, // Alpine doesn't provide security update tracking
		})
	}

	return packages
}

// extractAPKPackageNameAndVersion extracts package name and version from APK format
// e.g. "alpine-conf-3.20.0-r1" -> ("alpine-conf", "3.20.0-r1")
func extractAPKPackageNameAndVersion(packageWithVersion string) (string, string) {
	for i := 0; i < len(packageWithVersion); i++ {
		if packageWithVersion[i] == '-' && i+1 < len(packageWithVersion) {
			if packageWithVersion[i+1] >= '0' && packageWithVersion[i+1] <= '9' {
				return packageWithVersion[:i], packageWithVersion[i+1:]
			}
		}
	}
	return packageWithVersion, ""
}
