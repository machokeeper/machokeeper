//go:build linux && !amd64 && !arm64

package doctor

// sysSchedSetattr == 0 means "syscall number unknown here"; lowerPriority
// falls back to nice. machokeeper's Linux release targets are amd64/arm64.
const sysSchedSetattr = 0
