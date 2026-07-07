//go:build unix

package doctor

import (
	"os"
	"syscall"
)

// gcLockShared opens the GC lock and takes a shared (LOCK_SH) flock on
// it — the same primitive and mode nix's addTempRoot uses, so it
// interoperates with the daemon's exclusive GC lock. Blocking: if GC
// holds the exclusive lock, this waits, which is correct (do not repair
// during a collection). The returned unlock releases and closes.
func gcLockShared(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
