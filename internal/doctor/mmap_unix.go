//go:build unix

package doctor

import (
	"os"
	"syscall"
	"unsafe"
)

// madvDontneed drops the given pages from the page cache. syscall.Madvise
// is not exposed on darwin, so call SYS_MADVISE directly — the same on
// darwin and linux. MADV_DONTNEED is 4 on both.
func madvDontneed(b []byte) {
	if len(b) == 0 {
		return
	}
	const advDontneed = 4
	// unsafe is required to pass the mapping's base address to madvise;
	// b is a live mmap of len(b) bytes, so &b[0] is valid for the call.
	_, _, _ = syscall.Syscall( //nolint:gosec // G103: address of a live mmap passed to madvise(2)
		syscall.SYS_MADVISE,
		uintptr(unsafe.Pointer(&b[0])), //nolint:gosec // G103: as above
		uintptr(len(b)),
		advDontneed,
	)
}

// mmapRead maps `size` bytes of `f` read-only. Detection reads a few
// KiB at scattered offsets, so mapping keeps the pages clean and
// evictable — a large binary costs no heap. The returned unmap must be
// called once the bytes are no longer referenced. size must be > 0.
func mmapRead(f *os.File, size int64) (data []byte, unmap func(), err error) {
	b, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	return b, func() {
		// In a background sweep, drop the pages we faulted in so a
		// whole-store scan does not evict the user's warm page cache.
		// Interactive scans leave the cache alone (the user may run the
		// binary next). MADV_DONTNEED on a read-only MAP_SHARED just
		// releases clean pages; they re-fault from the file if needed.
		if background {
			madvDontneed(b)
		}
		_ = syscall.Munmap(b)
	}, nil
}
