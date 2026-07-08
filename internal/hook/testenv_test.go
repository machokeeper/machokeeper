package hook

import "os"

// The hook entry points pass --background to doctor; keep that from
// throttling the test binary.
func init() { _ = os.Setenv("MACHOKEEPER_NO_LOWER_PRIORITY", "1") }
