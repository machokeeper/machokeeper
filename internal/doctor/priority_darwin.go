//go:build darwin

package doctor

import "syscall"

// PRIO_DARWIN_PROCESS / PRIO_DARWIN_BG: darwin's setpriority extension.
// Setting a process to background throttles both its CPU scheduling and
// its disk I/O (IOPOL_THROTTLE) — the OS's own "be a good citizen" tier,
// the same one Time Machine and Spotlight use. It is process-wide (covers
// every thread), so it is the right place to throttle on darwin and the
// per-worker hook is unnecessary. No cgo needed (setpriority is a plain
// syscall).
const (
	prioDarwinProcess = 4
	prioDarwinBG      = 0x1000
)

func lowerProcessPriorityImpl() {
	_ = syscall.Setpriority(prioDarwinProcess, 0, prioDarwinBG)
}

// lowerScanThreadImpl is a no-op on darwin: PRIO_DARWIN_BG is process-wide,
// so the scan workers are already throttled.
func lowerScanThreadImpl() {}
