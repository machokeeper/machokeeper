//go:build unix

package doctor

import (
	"os"
	"syscall"
)

// mmapRead maps `size` bytes of `f` read-only. Detection reads a few
// KiB at scattered offsets, so mapping keeps the pages clean and
// evictable — a large binary costs no heap. The returned unmap must be
// called once the bytes are no longer referenced. size must be > 0.
func mmapRead(f *os.File, size int64) (data []byte, unmap func(), err error) {
	b, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	return b, func() { _ = syscall.Munmap(b) }, nil
}
