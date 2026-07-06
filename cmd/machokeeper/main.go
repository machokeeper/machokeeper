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
	"github.com/machokeeper/machokeeper/internal/hook"
	"github.com/machokeeper/machokeeper/internal/wrap"
)

const usage = `machokeeper — keep your Nix store's Mach-O binaries valid

Usage:
  machokeeper doctor [--fix] PATH...   diagnose (and with --fix, repair) files or store paths
  machokeeper doctor --scan [--fix]    scan the whole local Nix store
  machokeeper doctor --fix-live PATH   also repair GC-rooted paths (e.g. a login shell) in place
  machokeeper doctor --scan --json     machine-readable findings (implies report-only)
  machokeeper check PATH...            exit 2 if any signature is stale or unverifiable
  machokeeper wrap -- nix build ...    run a nix command, repairing what it substitutes first
  machokeeper version
  machokeeper help

Without --fix, doctor only reports. --fix repairs unrooted store paths
by re-registering them (correct NAR hash); --fix-live additionally
repairs rooted paths in place and reconciles their hash. Repair rewrites
only stale hash slots (byte-exact undo journal written next to the
report) and never touches Developer-ID-signed files or content-addressed
paths.`

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

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
	// Module-driven, non-interactive entry points (see the nix-darwin /
	// NixOS / home-manager module). All fail open.
	case "post-build-hook":
		os.Exit(hook.PostBuild())
	case "scan-generation":
		// scan-generation <new> [<old>] [--refuse]
		var newP, oldP, mode string
		mode = "repair"
		var rest []string
		for _, a := range os.Args[2:] {
			if a == "--refuse" {
				mode = "refuse"
			} else {
				rest = append(rest, a)
			}
		}
		if len(rest) > 0 {
			newP = rest[0]
		}
		if len(rest) > 1 {
			oldP = rest[1]
		}
		if newP == "" {
			fmt.Fprintln(os.Stderr, "scan-generation: need the new generation path")
			os.Exit(1)
		}
		os.Exit(hook.ScanGeneration(newP, oldP, mode))
	case "sweep":
		os.Exit(hook.Sweep())
	case "wrap":
		// machokeeper wrap -- nix build ...
		rest := os.Args[2:]
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		os.Exit(wrap.Run(rest))
	case "version", "--version":
		fmt.Printf("machokeeper %s\n", version)
	case "help", "--help", "-h":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", os.Args[1], usage)
		os.Exit(1)
	}
}
