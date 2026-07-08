//go:build linux && amd64

package doctor

// sched_setattr(2) syscall number on linux/amd64.
const sysSchedSetattr = 314
