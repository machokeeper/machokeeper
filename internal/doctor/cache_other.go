//go:build !linux

package doctor

import "os"

// dropScannedCache is a no-op off Linux. Darwin has no posix_fadvise;
// there the read-only MAP_SHARED mapping is the page-cache courtesy — its
// pages are clean, so the kernel reclaims them ahead of the user's
// working set under memory pressure, and PRIO_DARWIN_BG already throttles
// the scan's I/O rate.
func dropScannedCache(_ *os.File, _ int64) {}
