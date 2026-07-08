//go:build linux

package doctor

import (
	"runtime"
	"syscall"
	"unsafe"
)

// lowerScanThreadImpl pins the calling worker to its OS thread and lowers
// that thread's scheduling. nice/ioprio and the SCHED_IDLE policy are all
// per-thread on Linux, so a process-level call only throttles the main
// thread — each scan worker must lower its own. The thread stays pinned
// for the worker's life (fine; it just loops over the file channel) and
// is retired when the goroutine ends.
func lowerScanThreadImpl() {
	runtime.LockOSThread()
	lowerPriorityImpl()
}

// lowerPriorityImpl makes a background scan yield to interactive work.
//
//   - CPU: SCHED_IDLE — the task runs only when the CPU would otherwise
//     be idle, so foreground work is never slowed. This is stronger than
//     a positive nice, which still competes for CPU under load. Falls
//     back to nice +10 where sched_setattr is unavailable (pre-3.14
//     kernel, or blocked by seccomp).
//   - I/O: the idle I/O-priority class — honored by the BFQ/CFQ
//     schedulers (rotational disks); a harmless no-op under
//     mq-deadline/none (modern NVMe), where no unprivileged bandwidth
//     throttle exists anyway.
func lowerPriorityImpl() {
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

// setSchedIdle switches the calling thread to SCHED_IDLE via
// sched_setattr, returning false if it is unavailable. The sched_attr
// layout is fixed ABI: size u32, policy u32, flags u64, nice s32, prio
// u32, runtime u64, deadline u64, period u64 (48 bytes); only size and
// policy matter for SCHED_IDLE.
func setSchedIdle() bool {
	if sysSchedSetattr == 0 {
		return false // syscall number unknown on this arch
	}
	const schedIdle = 5
	var attr [48]byte
	//nolint:gosec // G103: writing the fixed-layout sched_attr we pass to the kernel
	*(*uint32)(unsafe.Pointer(&attr[0])) = uint32(len(attr)) // size
	//nolint:gosec // G103: as above
	*(*uint32)(unsafe.Pointer(&attr[4])) = schedIdle // sched_policy
	//nolint:gosec // G103: address of the local sched_attr passed to sched_setattr(2)
	_, _, errno := syscall.Syscall(uintptr(sysSchedSetattr), 0, uintptr(unsafe.Pointer(&attr[0])), 0)
	return errno == 0
}
