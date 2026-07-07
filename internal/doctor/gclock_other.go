//go:build !unix

package doctor

import "errors"

// gcLockShared is unavailable off unix; withGCLock falls back to running
// without the lock. machokeeper targets darwin and linux.
func gcLockShared(_ string) (func(), error) {
	return nil, errors.New("flock not supported on this platform")
}
