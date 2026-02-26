package packages

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var (
	installedPkgRe = regexp.MustCompile(`^(\S+)\s+(\S+)$`)
	checkUpdateRe  = regexp.MustCompile(`^(\S+)\s+(\S+)\s+->\s+(\S+)$`)
)

// PacmanManager handles pacman package information collection
type PacmanManager struct{}

// GetPackages gets package information for pacman-based systems (Arch Linux)
func (m *PacmanManager) GetPackages() ([]PackageInfo, error) {
	// Get installed packages
	installedCmd := exec.Command("pacman", "-Q")
	installedOutput, err := installedCmd.Output()
	var installedPackages map[string]string
	if err != nil {
		fmt.Printf("  packages: failed to get installed packages: %v\n", err)
		installedPackages = make(map[string]string)
	} else {
		installedPackages = m.parseInstalledPackages(string(installedOutput))
	}

	upgradablePackages, err := m.getUpgradablePackages()
	if err != nil {
		return nil, err
	}

	return CombinePackageData(installedPackages, upgradablePackages), nil
}

// getUpgradablePackages runs checkupdates and returns parsed packages
func (m *PacmanManager) getUpgradablePackages() ([]PackageInfo, error) {
	if _, err := exec.LookPath("checkupdates"); err != nil {
		return nil, fmt.Errorf("checkupdates not found (pacman-contrib not installed)")
	}

	upgradeCmd := exec.Command("checkupdates")
	upgradeOutput, err := upgradeCmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 2 {
				return []PackageInfo{}, nil
			}
		}
		return nil, fmt.Errorf("checkupdates failed: %w", err)
	}

	return m.parseCheckUpdate(string(upgradeOutput)), nil
}

// parseCheckUpdate parses checkupdates output
func (m *PacmanManager) parseCheckUpdate(output string) []PackageInfo {
	var packages []PackageInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		matches := checkUpdateRe.FindStringSubmatch(scanner.Text())
		if matches == nil {
			continue
		}

		packages = append(packages, PackageInfo{
			Name:             matches[1],
			CurrentVersion:   matches[2],
			AvailableVersion: matches[3],
			NeedsUpdate:      true,
		})
	}

	return packages
}

// parseInstalledPackages parses pacman -Q output
func (m *PacmanManager) parseInstalledPackages(output string) map[string]string {
	installedPackages := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		matches := installedPkgRe.FindStringSubmatch(scanner.Text())
		if matches == nil {
			continue
		}
		installedPackages[matches[1]] = matches[2]
	}

	return installedPackages
}
