// Package wrap implements `machokeeper wrap -- <nix command>`: run a
// nix command with broken substituted binaries repaired first, so a
// command that both substitutes and *uses* a binary (e.g. direnv's
// checkPhase running a just-substituted fish) doesn't fail mid-flight.
//
// It needs no proxy and no signing keys: a dry run lists what the
// command would substitute, those paths are realised and repaired, then
// the real command runs unmodified. The dry-run list is best-effort
// (import-from-derivation and impure evaluation can diverge), so a
// failed run is retried once after a repair sweep of what it did pull.
package wrap

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/machokeeper/machokeeper/internal/doctor"
)

// Run implements `machokeeper wrap -- <argv...>`. argv is the nix
// command to run (e.g. ["nix" "build" ".#foo"]).
func Run(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "wrap: no command given (usage: machokeeper wrap -- nix build ...)")
		return 1
	}

	// Pre-fetch pass: ask nix what it would substitute, realise and
	// repair those paths before the real run uses them.
	if subs := willSubstitute(argv); len(subs) > 0 {
		if realised := realise(subs); len(realised) > 0 {
			doctor.Run(append([]string{"--fix", "--quiet"}, realised...))
		}
	}

	// Run the real command.
	rc := passthrough(argv)
	if rc == 0 {
		return 0
	}

	// It failed. A common cause is a binary that was substituted and
	// used within the run before the pre-fetch could reach it (IFD, an
	// impure path, a dependency pulled mid-build). Repair everything the
	// command's derivations reference, then retry once.
	if repaired := repairClosureOf(argv); repaired {
		return passthrough(argv)
	}
	return rc
}

// willSubstitute returns the store paths the command would fetch from a
// substituter, via a dry run. Best-effort: parse the machine-readable
// build log for substitution events.
func willSubstitute(argv []string) []string {
	dry := append([]string{}, argv...)
	dry = append(dry, "--dry-run", "--log-format", "internal-json")
	cmd := exec.Command(dry[0], dry[1:]...)
	out, _ := cmd.CombinedOutput() // dry-run failures are non-fatal here
	var subs []string
	for _, line := range strings.Split(string(out), "\n") {
		// internal-json substitution events name the path in `fields`.
		// A robust-enough heuristic without a full JSON schema: any
		// /nix/store/… token on a "copying"/"substituting" line.
		if strings.Contains(line, "substitut") || strings.Contains(line, "copying path") {
			for _, tok := range strings.Fields(strings.ReplaceAll(line, "\"", " ")) {
				if strings.HasPrefix(tok, "/nix/store/") {
					subs = append(subs, cleanPath(tok))
				}
			}
		}
	}
	return dedupe(subs)
}

// realise ensures the given paths exist locally (fetching them), and
// returns those that now exist.
func realise(paths []string) []string {
	var ok []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			ok = append(ok, p)
			continue
		}
		if err := exec.Command("nix-store", "--realise", p).Run(); err == nil {
			ok = append(ok, p)
		}
	}
	return ok
}

// repairClosureOf realises and repairs the full closure of whatever the
// command references, as a fallback after a failed run. Returns true if
// it repaired anything.
func repairClosureOf(argv []string) bool {
	// Re-run the dry list; if empty, nothing to do.
	subs := willSubstitute(argv)
	realised := realise(subs)
	if len(realised) == 0 {
		return false
	}
	rc := doctor.Run(append([]string{"--fix", "--quiet"}, realised...))
	return rc == 0
}

func passthrough(argv []string) int {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}

func cleanPath(p string) string {
	// Trim to the top-level store path (…/<hash>-<name>), dropping any
	// trailing narinfo suffix or sub-path.
	const prefix = "/nix/store/"
	rest := p[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, ".narinfo")
	return prefix + rest
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
