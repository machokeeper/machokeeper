//go:build !darwin && !linux

package doctor

// lowerPriority is a no-op off darwin/linux. machokeeper targets those.
func lowerPriorityImpl() {}

func lowerScanThreadImpl() {}
