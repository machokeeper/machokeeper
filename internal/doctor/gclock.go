package doctor

import (
	"os"
	"path/filepath"
)

// gcLockPath is nix's "big garbage collector lock". GC takes it
// exclusively (LOCK_EX); store writes and optimise take it shared
// (LOCK_SH). Holding it shared across a store-path repair blocks a
// concurrent `nix-store --gc` from collecting the path mid-repair,
// matching how the daemon itself coordinates (addTempRoot takes the
// same shared lock). Overridable for tests so they never touch the
// real daemon lock; "" disables the coordination.
var gcLockPath = defaultGCLockPath()

func defaultGCLockPath() string {
	dir := os.Getenv("NIX_STATE_DIR")
	if dir == "" {
		dir = "/nix/var/nix"
	}
	return filepath.Join(dir, "gc.lock")
}

// withGCLock runs fn while holding a shared lock on the nix GC lock.
// Best-effort: if the lock cannot be acquired (missing, permissions,
// unsupported platform), fn runs anyway — the repair is atomic,
// hardlink-safe, and hash-reconciled, so a lost GC race is detectable
// (`nix-store --verify`) and self-healing on a re-run, not corrupting.
// The shared lock deliberately does NOT exclude a concurrent
// `nix-store --optimise` (also shared); that race stays narrow and
// benign for the same reason (see docs/DESIGN.md).
func withGCLock(fn func() error) error {
	if gcLockPath == "" {
		return fn()
	}
	unlock, err := gcLockShared(gcLockPath)
	if err != nil {
		return fn() // best-effort
	}
	defer unlock()
	return fn()
}
