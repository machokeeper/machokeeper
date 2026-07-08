//go:build linux && arm64

package doctor

// sched_setattr(2) syscall number on linux/arm64.
const sysSchedSetattr = 274
