//go:build !unix

package doctor

import (
	"errors"
	"os"
)

// mmapRead is unavailable off unix; scanFile falls back to a bounded
// read. machokeeper targets darwin and linux, so this path is only for
// portability of the build.
func mmapRead(_ *os.File, _ int64) ([]byte, func(), error) {
	return nil, nil, errors.New("mmap not supported on this platform")
}
