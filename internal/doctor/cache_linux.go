//go:build linux

package doctor

import (
	"os"
	"syscall"
)

// dropScannedCache tells the kernel it can drop the file's clean pages
// from the page cache — posix_fadvise(POSIX_FADV_DONTNEED). Called after
// the mapping is torn down in a background sweep, so scanning the whole
// store does not evict the user's warm cache. (madvise(MADV_DONTNEED) on
// the mapping would only affect this process's page tables, not the
// global cache; fadvise is the tool that actually reclaims the pages.)
// Best-effort: a failure just leaves the pages cached.
func dropScannedCache(f *os.File, size int64) {
	const posixFadvDontneed = 4
	_, _, _ = syscall.Syscall6(
		syscall.SYS_FADVISE64,
		f.Fd(),
		0,
		uintptr(size),
		posixFadvDontneed,
		0, 0,
	)
}
