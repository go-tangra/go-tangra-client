package packages

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// APTManager handles APT package information collection
type APTManager struct{}

// detectPackageManager detects whether to use apt or apt-get
func (m *APTManager) detectPackageManager() string {
	if _, err := exec.LookPath("/usr/bin/apt"); err == nil {
		return "/usr/bin/apt"
	}
	if _, err := exec.LookPath("apt"); err == nil {
		return "apt"
	}
	return "apt-get"
}

// GetPackages gets package information for APT-based systems
func (m *APTManager) GetPackages() []PackageInfo {
	packageManager := m.detectPackageManager()

	// Get installed packages
	installedCmd := exec.Command("dpkg-query", "-W", "-f", "${Package} ${Version} ${Description}\n")
	installedCmd.Env = append(os.Environ(), "LANG=C")
	installedOutput, err := installedCmd.Output()
	var installedPackages map[string]PackageInfo
	if err != nil {
		fmt.Printf("  packages: failed to get installed packages: %v\n", err)
		installedPackages = make(map[string]PackageInfo)
	} else {
		installedPackages = m.parseInstalledPackages(string(installedOutput))
	}

	// Get upgradable packages using apt simulation
	upgradeCmd := exec.Command(packageManager, "-s", "-o", "Debug::NoLocking=1", "upgrade")
	upgradeOutput, err := upgradeCmd.Output()
	var upgradablePackages []PackageInfo
	if err != nil {
		upgradablePackages = []PackageInfo{}
	} else {
		upgradablePackages = m.parseAPTUpgrade(string(upgradeOutput))
	}

	// Convert to simple map for CombinePackageData
	installedMap := make(map[string]string)
	for name, pkg := range installedPackages {
		installedMap[name] = pkg.CurrentVersion
	}

	return CombinePackageData(installedMap, upgradablePackages)
}

// parseAPTUpgrade parses apt/apt-get upgrade simulation output
func (m *APTManager) parseAPTUpgrade(output string) []PackageInfo {
	var packages []PackageInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "Inst ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		packageName := fields[1]

		// Extract current version (in brackets)
		var currentVersion string
		for i, field := range fields {
			if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
				currentVersion = strings.Trim(field, "[]")
				break
			} else if after, found := strings.CutPrefix(field, "["); found {
				versionParts := []string{after}
				for j := i + 1; j < len(fields); j++ {
					if strings.HasSuffix(fields[j], "]") {
						versionParts = append(versionParts, strings.TrimSuffix(fields[j], "]"))
						break
					}
					versionParts = append(versionParts, fields[j])
				}
				currentVersion = strings.Join(versionParts, " ")
				break
			}
		}

		// Extract available version (in parentheses)
		var availableVersion string
		for _, field := range fields {
			if after, found := strings.CutPrefix(field, "("); found {
				availableVersion = after
				break
			}
		}

		isSecurityUpdate := strings.Contains(strings.ToLower(line), "security")

		if packageName != "" && currentVersion != "" && availableVersion != "" {
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

// parseInstalledPackages parses dpkg-query output
func (m *APTManager) parseInstalledPackages(output string) map[string]PackageInfo {
	installedPackages := make(map[string]PackageInfo)

	scanner := bufio.NewScanner(strings.NewReader(output))
	var currentPkg *PackageInfo

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}

		// Description continuation line (starts with space)
		if strings.HasPrefix(line, " ") && currentPkg != nil {
			currentPkg.Description += "\n" + trimmedLine
			installedPackages[currentPkg.Name] = *currentPkg
			continue
		}

		parts := strings.SplitN(trimmedLine, " ", 3)
		if len(parts) < 2 {
			currentPkg = nil
			continue
		}

		packageName := parts[0]
		version := parts[1]
		description := ""
		if len(parts) == 3 {
			description = parts[2]
		}

		pkg := PackageInfo{
			Name:           packageName,
			CurrentVersion: version,
			Description:    description,
		}
		installedPackages[packageName] = pkg
		currentPkg = &pkg
	}

	return installedPackages
}
