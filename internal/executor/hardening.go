package executor

import "os"

// DetectSecurityHardened probes whether this process runs under systemd
// filesystem sandboxing (ProtectSystem=strict/full, ProtectHome, ReadOnlyPaths,
// …) that would make most host-ops actions fail. Those directives mount the
// system read-only inside the unit's namespace, so a root daemon can no longer
// write to /etc, /usr, /var — exactly the paths file/service/package actions
// touch.
//
// It probes by trying to create (then remove) a tiny file under representative
// system directories. If it cannot write them, the host is reported as hardened
// (true), since that is precisely the condition under which actions break. It is
// best-effort and never errors: a hardened result simply tells the operator that
// even an actions-enabled host will likely fail to apply changes.
func DetectSecurityHardened() bool {
	// ProtectSystem=strict makes the whole hierarchy read-only; strict/full both
	// cover /etc and /usr. If either is unwritable, the sandbox is active.
	for _, dir := range []string{"/etc", "/usr"} {
		if !probeWritable(dir) {
			return true
		}
	}
	return false
}

// probeWritable reports whether a probe file can be created in dir. A read-only
// filesystem (systemd sandbox) returns false.
func probeWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".tangra-hardening-probe-")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}
