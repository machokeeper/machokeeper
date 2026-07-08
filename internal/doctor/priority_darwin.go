//go:build darwin

package doctor

import "syscall"

// PRIO_DARWIN_PROCESS / PRIO_DARWIN_BG: darwin's setpriority extension.
// Setting a process to background throttles both its CPU scheduling and
// its disk I/O (IOPOL_THROTTLE) — the OS's own "be a good citizen"
// tier, the same one Time Machine and Spotlight use. One call covers
// CPU and I/O; no cgo needed (setpriority is a plain syscall).
const (
	prioDarwinProcess = 4
	prioDarwinBG      = 0x1000
)

func lowerPriorityImpl() {
	_ = syscall.Setpriority(prioDarwinProcess, 0, prioDarwinBG)
}

// lowerScanThreadImpl is a no-op on darwin: PRIO_DARWIN_BG set by
// lowerPriorityImpl is process-wide, so the workers are already throttled.
func lowerScanThreadImpl() {}
