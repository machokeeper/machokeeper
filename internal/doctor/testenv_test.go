package doctor

import "os"

// Never throttle the in-process test binary via the module hooks' --background.
func init() { _ = os.Setenv("MACHOKEEPER_NO_LOWER_PRIORITY", "1") }
