//go:build linux

package doctor

import (
	"runtime"
	"syscall"
)

// lowerScanThreadImpl pins the calling worker to its OS thread and lowers
// that thread's nice / I/O class. nice and ioprio are per-thread on
// Linux, so a process-level call only throttles the main thread — each
// scan worker must lower its own. The thread stays pinned for the
// worker's life (fine; the worker just loops over the file channel) and
// is retired when the goroutine ends.
func lowerScanThreadImpl() {
	runtime.LockOSThread()
	lowerPriorityImpl()
}

// lowerPriority makes a background scan yield to interactive work: a
// +10 nice for CPU, and the idle I/O-priority class for disk (effective
// under the BFQ/CFQ schedulers; a harmless no-op under mq-deadline/none).
func lowerPriorityImpl() {
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)

	const (
		ioprioWhoProcess = 1
		ioprioClassIdle  = 3
		ioprioClassShift = 13
	)
	ioprio := uintptr(ioprioClassIdle << ioprioClassShift)
	// ioprio_set(IOPRIO_WHO_PROCESS, self, IOPRIO_CLASS_IDLE). Best
	// effort: a failure just leaves the default I/O class.
	_, _, _ = syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprio)
}
