//go:build linux

package doctor

import (
	"runtime"
	"syscall"
	"unsafe"
)

// lowerProcessPriorityImpl is a no-op on Linux: nice, the I/O class, and
// SCHED_IDLE are all per-thread, so there is no process-wide throttle to
// set here. Each scan worker lowers its own thread (lowerScanThreadImpl);
// the main thread only walks directories (light) and runs the serial
// repair, which is left at normal priority so a --fix is not stalled.
func lowerProcessPriorityImpl() {}

// lowerScanThreadImpl pins the calling worker to its OS thread and lowers
// that thread's scheduling, so the parallel scan (the CPU/I/O hog) yields
// to interactive work:
//
//   - CPU: SCHED_IDLE — the thread runs only when a CPU would otherwise
//     be idle, so foreground work is never slowed. Stronger than a
//     positive nice, which still competes under load. Falls back to nice
//     +10 where sched_setattr is unavailable (pre-3.14 kernel or seccomp).
//   - I/O: the idle I/O-priority class — honored by BFQ/CFQ (rotational);
//     a harmless no-op under mq-deadline/none (modern NVMe), where no
//     unprivileged bandwidth throttle exists anyway.
//
// The thread stays pinned for the worker's life (it just loops over the
// file channel) and is retired when the goroutine ends.
func lowerScanThreadImpl() {
	runtime.LockOSThread()

	if !setSchedIdle() {
		_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
	}

	const (
		ioprioWhoProcess = 1
		ioprioClassIdle  = 3
		ioprioClassShift = 13
	)
	ioprio := uintptr(ioprioClassIdle << ioprioClassShift)
	_, _, _ = syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprio)
}

// schedAttr mirrors the kernel's struct sched_attr (sched_setattr(2)).
// Natural Go alignment matches the ABI exactly: 48 bytes, fields at
// 0/4/8/16/20/24/32/40. Only size and policy are set for SCHED_IDLE.
type schedAttr struct {
	size     uint32
	policy   uint32
	flags    uint64
	nice     int32
	priority uint32
	runtime  uint64
	deadline uint64
	period   uint64
}

// setSchedIdle switches the calling thread to SCHED_IDLE via
// sched_setattr, returning false if it is unavailable.
func setSchedIdle() bool {
	if sysSchedSetattr == 0 {
		return false // syscall number unknown on this arch
	}
	const schedIdle = 5
	attr := schedAttr{size: uint32(unsafe.Sizeof(schedAttr{})), policy: schedIdle}
	//nolint:gosec // G103: address of the local sched_attr passed to sched_setattr(2)
	_, _, errno := syscall.Syscall(uintptr(sysSchedSetattr), 0, uintptr(unsafe.Pointer(&attr)), 0)
	return errno == 0
}
