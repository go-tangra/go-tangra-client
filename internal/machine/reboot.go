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

// detectUnattendedUpgrades reports whether automatic OS updates are enabled.
// On apt systems it consults the authoritative merged apt config
// (APT::Periodic::Unattended-Upgrade "1"); on dnf systems it checks whether the
// dnf-automatic timer is enabled.
func detectUnattendedUpgrades() bool {
	return aptUnattendedEnabled() || timerEnabled("dnf-automatic.timer") ||
		timerEnabled("dnf-automatic-install.timer")
}

// aptUnattendedEnabled returns true when apt's merged config sets
// APT::Periodic::Unattended-Upgrade to "1". apt-config dump merges every file
// under /etc/apt/apt.conf.d, so it is authoritative; absent apt-config means
// this is not an apt host.
func aptUnattendedEnabled() bool {
	if _, err := exec.LookPath("apt-config"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "apt-config", "dump", "APT::Periodic::Unattended-Upgrade").Output()
	if err != nil {
		return false
	}
	// Output is `APT::Periodic::Unattended-Upgrade "1";` when enabled, "0" or
	// empty otherwise.
	return strings.Contains(string(out), `"1"`)
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
