// machokeeper keeps a Nix store's Mach-O binaries valid: it detects,
// reports, and (on request) repairs code signatures whose page hashes
// no longer match the file contents — the breakage behind
// NixOS/nixpkgs#507531 and NixOS/nix#6065 that macOS kills with
// SIGKILL (cs_invalid_page) at launch.
package main

import (
	"fmt"
	"os"

	"github.com/machokeeper/machokeeper/internal/doctor"
)

const usage = `machokeeper — keep your Nix store's Mach-O binaries valid

Usage:
  machokeeper doctor [--fix] PATH...   diagnose (and with --fix, repair) files or store paths
  machokeeper doctor --scan [--fix]    scan the whole local Nix store
  machokeeper check PATH...            exit 2 if any signature is stale or unverifiable
  machokeeper help

Without --fix, doctor only reports. Repair rewrites only stale hash
slots (byte-exact undo journal written next to the report) and never
touches Developer-ID-signed files or content-addressed paths.`

func main() {
	if len(os.Args) < 2 {
		fmt.Println(usage)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "doctor":
		os.Exit(doctor.Run(os.Args[2:]))
	case "check":
		os.Exit(doctor.Check(os.Args[2:]))
	case "help", "--help", "-h":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", os.Args[1], usage)
		os.Exit(1)
	}
}
