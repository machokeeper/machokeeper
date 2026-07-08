// Package hook implements the non-interactive entry points the
// nix-darwin / NixOS / home-manager module wires in: the post-build
// hook, the activation scan, and the first-enable sweep. All of them
// fail open — they never exit non-zero for a signature problem, so a
// build or a system switch can never fail because of machokeeper — and
// they default to repair, since the module being enabled is the user's
// consent to repair.
package hook

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/machokeeper/machokeeper/internal/doctor"
)

// PostBuild implements `machokeeper post-build-hook`: repair just-built
// outputs before they are first used. Nix passes the built paths in
// $OUT_PATHS (space-separated). Runs as the build user (or root in
// daemon mode). Always exits 0.
func PostBuild() int {
	outPaths := strings.Fields(os.Getenv("OUT_PATHS"))
	if len(outPaths) == 0 {
		return 0
	}
	// --fix (not --fix-live): a freshly built output is not yet a GC
	// root, so the re-registering path applies and keeps the hash
	// correct. Quiet unless something is repaired.
	// --background: the module runs this off the interactive path, so
	// yield CPU/I/O to the user and don't evict their page cache.
	args := append([]string{"--fix", "--quiet", "--background"}, outPaths...)
	doctor.Run(args)
	return 0
}

// ScanGeneration implements `machokeeper scan-generation`: repair every
// new store path in an incoming system/home generation, before it goes
// live. The module runs this during activation, after substitution.
// Given the new and old top-level paths, it scans only the closure
// delta. Mode is "repair" (default) or "refuse" (fail the switch if
// anything is broken — chosen by the operator). Always exits 0 in
// repair mode.
func ScanGeneration(newPath, oldPath, mode string) int {
	delta, err := closureDelta(newPath, oldPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "machokeeper: computing closure delta: %v\n", err)
		return 0 // fail open: never block a switch
	}
	if len(delta) == 0 {
		return 0
	}
	if mode == "refuse" {
		args := append([]string{"--background"}, delta...)
		if rc := doctor.Check(args); rc == 2 {
			fmt.Fprintln(os.Stderr, "machokeeper: refusing activation — the new generation contains broken Mach-O signatures (set services.machokeeper.onActivation = \"repair\" to fix them instead)")
			return 1
		}
		return 0
	}
	args := append([]string{"--fix", "--background"}, delta...)
	doctor.Run(args)
	return 0
}

// Sweep implements `machokeeper sweep`: a one-shot repair of the whole
// store, run once when the module is first enabled. Always exits 0.
func Sweep() int {
	doctor.Run([]string{"--scan", "--fix", "--background"})
	return 0
}

// closureDelta returns the store paths in newPath's closure that are not
// in oldPath's closure. With no oldPath it returns newPath's whole
// closure.
func closureDelta(newPath, oldPath string) ([]string, error) {
	newClosure, err := requisitesFn(newPath)
	if err != nil {
		return nil, err
	}
	if oldPath == "" {
		return newClosure, nil
	}
	oldClosure, err := requisitesFn(oldPath)
	if err != nil {
		// If the old generation is gone, scan the whole new closure.
		return newClosure, nil
	}
	old := make(map[string]struct{}, len(oldClosure))
	for _, p := range oldClosure {
		old[p] = struct{}{}
	}
	var delta []string
	for _, p := range newClosure {
		if _, seen := old[p]; !seen {
			delta = append(delta, p)
		}
	}
	return delta, nil
}

// requisitesFn is the closure query, injectable for tests.
var requisitesFn = requisites

func requisites(path string) ([]string, error) {
	out, err := exec.Command("nix-store", "--query", "--requisites", path).Output()
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths, nil
}
