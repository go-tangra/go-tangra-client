package packages

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DNFManager handles dnf/yum package information collection
type DNFManager struct{}

// detectPackageManager detects whether to use dnf or yum
func (m *DNFManager) detectPackageManager() string {
	if _, err := exec.LookPath("dnf"); err == nil {
		return "dnf"
	}
	return "yum"
}

// GetPackages gets package information for RHEL-based systems
func (m *DNFManager) GetPackages() []PackageInfo {
	packageManager := m.detectPackageManager()

	// Refresh package metadata
	makecacheCmd := exec.Command(packageManager, "makecache", "-q")
	makecacheCmd.Env = append(os.Environ(), "LANG=C")
	if err := makecacheCmd.Run(); err != nil {
		fmt.Printf("  packages: %s makecache failed (continuing): %v\n", packageManager, err)
	}

	// Get installed packages
	listCmd := exec.Command(packageManager, "list", "installed")
	listCmd.Env = append(os.Environ(), "LANG=C")
	installedOutput, err := listCmd.Output()
	var installedPackages map[string]PackageInfo
	if err != nil {
		fmt.Printf("  packages: failed to get installed packages: %v\n", err)
		installedPackages = make(map[string]PackageInfo)
	} else {
		installedPackages = m.parseInstalledPackages(string(installedOutput))
	}

	// Get security updates
	securityPackages := m.getSecurityPackages(packageManager)

	// Get upgradable packages
	checkCmd := exec.Command(packageManager, "check-update")
	checkOutput, _ := checkCmd.Output() // Returns exit code 100 when updates available

	var upgradablePackages []PackageInfo
	if len(checkOutput) > 0 {
		upgradablePackages = m.parseUpgradablePackages(string(checkOutput), packageManager, installedPackages, securityPackages)
	}

	return CombinePackageData(installedPackages, upgradablePackages)
}

// getSecurityPackages gets security packages from dnf/yum updateinfo
func (m *DNFManager) getSecurityPackages(packageManager string) map[string]bool {
	securityPackages := make(map[string]bool)

	updateInfoCmd := exec.Command(packageManager, "updateinfo", "list", "security")
	updateInfoOutput, err := updateInfoCmd.Output()
	if err != nil {
		updateInfoCmd = exec.Command(packageManager, "updateinfo", "list", "sec")
		updateInfoOutput, err = updateInfoCmd.Output()
	}
	if err != nil {
		return securityPackages
	}

	scanner := bufio.NewScanner(strings.NewReader(string(updateInfoOutput)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "Last metadata") ||
			strings.Contains(line, "expiration") || strings.HasPrefix(line, "Loading") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		advisoryID := fields[0]
		isAdvisory := strings.HasPrefix(advisoryID, "RHSA") ||
			strings.HasPrefix(advisoryID, "ALSA") ||
			strings.HasPrefix(advisoryID, "ELSA") ||
			strings.HasPrefix(advisoryID, "CESA")
		if !isAdvisory {
			continue
		}

		basePackageName := extractBasePackageName(fields[2])
		if basePackageName != "" {
			securityPackages[basePackageName] = true
		}
	}

	return securityPackages
}

// parseUpgradablePackages parses dnf/yum check-update output
func (m *DNFManager) parseUpgradablePackages(output string, packageManager string, installedPackages map[string]PackageInfo, securityPackages map[string]bool) []PackageInfo {
	var packages []PackageInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "Loaded plugins") ||
			strings.Contains(line, "Last metadata") || strings.HasPrefix(line, "Loading") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		rawName := fields[0]
		packageName := stripArchSuffix(rawName)
		availableVersion := fields[1]

		// Get current version from installed packages
		var currentVersion string
		if p, ok := installedPackages[packageName]; ok {
			currentVersion = p.CurrentVersion
		}

		// Fallback: query directly using original name with arch
		if currentVersion == "" {
			getCurrentCmd := exec.Command(packageManager, "list", "installed", rawName)
			if getCurrentOutput, err := getCurrentCmd.Output(); err == nil {
				for _, currentLine := range strings.Split(string(getCurrentOutput), "\n") {
					if strings.Contains(currentLine, rawName) && !strings.Contains(currentLine, "Installed") && !strings.Contains(currentLine, "Available") {
						currentFields := strings.Fields(currentLine)
						if len(currentFields) >= 2 {
							currentVersion = currentFields[1]
							break
						}
					}
				}
			}
		}

		if packageName != "" && currentVersion != "" && availableVersion != "" {
			basePackageName := extractBasePackageName(packageName)
			isSecurityUpdate := securityPackages[basePackageName]

			packages = append(packages, PackageInfo{
				Name:             packageName,
				CurrentVersion:   currentVersion,
				AvailableVersion: availableVersion,
				NeedsUpdate:      true,
				IsSecurityUpdate: isSecurityUpdate,
			})
		}
	}

	return packages
}

// parseInstalledPackages parses dnf list installed output
func (m *DNFManager) parseInstalledPackages(output string) map[string]PackageInfo {
	installedPackages := make(map[string]PackageInfo)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Installed Packages") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		packageName := stripArchSuffix(parts[0])
		version := parts[1]

		installedPackages[packageName] = PackageInfo{
			Name:           packageName,
			CurrentVersion: version,
		}
	}

	return installedPackages
}
