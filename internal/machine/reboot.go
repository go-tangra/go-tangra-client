package machine

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// detectRebootRequired reports whether the host needs a reboot. It first checks
// the Debian/Ubuntu sentinel file (written by update-notifier after a package
// upgrade that needs a restart), then falls back to needrestart's kernel status
// when that tool is installed (covers RPM-based and minimal systems too).
func detectRebootRequired() bool {
	// /var/run is a symlink to /run on modern systems; check both for safety.
	for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return needrestartKernelReboot()
}

// needrestartKernelReboot runs `needrestart -b -k` (batch, kernel-only) and
// reports whether the running kernel needs a reboot. needrestart prints
// `NEEDRESTART-KSTA: N`, where N is 0=unknown, 1=current (no reboot), 2=ABI
// upgrade pending, 3=version upgrade pending — N>=2 means a reboot is needed.
// Returns false when needrestart is absent or unparseable (best effort).
func needrestartKernelReboot() bool {
	if _, err := exec.LookPath("needrestart"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// -k limits the check to the kernel (skips the slow service scan); -b is
	// batch (non-interactive) output. We parse stdout regardless of exit code.
	out, _ := exec.CommandContext(ctx, "needrestart", "-b", "-k").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "NEEDRESTART-KSTA:"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 2 {
				return true
			}
		}
	}
	return false
}

// detectUnattendedUpgrades reports whether automatic OS updates will actually
// run. On apt systems that requires BOTH the periodic config
// (APT::Periodic::Unattended-Upgrade "1") AND the apt-daily-upgrade.timer being
// enabled. On dnf systems it is whether the dnf-automatic timer is enabled.
func detectUnattendedUpgrades() bool {
	return aptUnattendedEnabled() || timerEnabled("dnf-automatic.timer") ||
		timerEnabled("dnf-automatic-install.timer")
}

// aptUnattendedEnabled reports whether apt unattended upgrades will run. The
// periodic config must request them AND the systemd timer that triggers them
// must be enabled — config "1" with the timer disabled/masked does nothing, and
// the timer with config "0" likewise does nothing. The unattended-upgrades
// *service* unit is only the shutdown-time helper (not the periodic trigger), so
// its enabled/disabled state is intentionally NOT used here.
func aptUnattendedEnabled() bool {
	return aptPeriodicUnattendedOn() && timerEnabled("apt-daily-upgrade.timer")
}

// aptPeriodicUnattendedOn reports whether APT::Periodic::Unattended-Upgrade is
// "1" in apt's merged config. It parses the exact key line so a stray "1" from
// any other config value can never match.
func aptPeriodicUnattendedOn() bool {
	if _, err := exec.LookPath("apt-config"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "apt-config", "dump", "APT::Periodic::Unattended-Upgrade").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "APT::Periodic::Unattended-Upgrade"); ok {
			return strings.Contains(v, `"1"`)
		}
	}
	return false
}

// timerEnabled reports whether a systemd timer unit is enabled.
func timerEnabled(unit string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "is-enabled", unit).Output()
	return strings.TrimSpace(string(out)) == "enabled"
}
