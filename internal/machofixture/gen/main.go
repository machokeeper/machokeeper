// Command gen writes machofixture's byte blobs to files, so non-Go
// harnesses (the NixOS VM integration test) can place real broken,
// repairable, and unrepairable Mach-O binaries into a live store.
//
// Usage: go run ./internal/machofixture/gen <outdir>
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/machokeeper/machokeeper/internal/machofixture"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen <outdir>")
		os.Exit(1)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, blob := range map[string][]byte{
		"repairable": machofixture.Repairable(3),
		"cms":        machofixture.CMS(2),
		"unsigned":   machofixture.Unsigned(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), blob, 0o755); err != nil { //nolint:gosec // fixtures are mock executables; the VM test execs nothing
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
