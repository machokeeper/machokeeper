//go:build !darwin && !linux

package doctor

// No priority control off darwin/linux. machokeeper targets those.
func lowerProcessPriorityImpl() {}
func lowerScanThreadImpl()      {}
