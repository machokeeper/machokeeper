//go:build linux

package doctor

import "syscall"

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
