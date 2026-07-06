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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/machokeeper/machokeeper/internal/doctor"
)

// Injectable seams so the orchestration (pre-fetch, run, repair-sweep,
// retry-once) is testable without nix or a store.
var (
	willSubstituteFn = willSubstitute
	realiseFn        = realise
	passthroughFn    = passthrough
	fixFn            = func(paths []string) int {
		return doctor.Run(append([]string{"--fix", "--quiet"}, paths...))
	}
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
	if subs := willSubstituteFn(argv); len(subs) > 0 {
		if realised := realiseFn(subs); len(realised) > 0 {
			fixFn(realised)
		}
	}

	// Run the real command.
	rc := passthroughFn(argv)
	if rc == 0 {
		return 0
	}

	// It failed. A common cause is a binary that was substituted and
	// used within the run before the pre-fetch could reach it (IFD, an
	// impure path, a dependency pulled mid-build). Repair everything the
	// dry run now reports, then retry once.
	if repaired := repairSubstitutes(argv); repaired {
		return passthroughFn(argv)
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
	return parseSubstitutePaths(string(out))
}

// nixLogEvent is the subset of nix's internal-json log schema wrap
// needs. Two event shapes carry substitution paths:
//
//   - a dry run prints plain messages, "this path will be fetched"
//     followed by indented store paths (action "msg");
//   - a live run starts a copy-path activity (action "start", type
//     100) whose first field is the store path, and substitution
//     queries (type 109) name the path the same way.
//
// internal-json is not a stable interface, so unknown shapes are
// ignored and wrap stays best-effort by design.
type nixLogEvent struct {
	Action string            `json:"action"`
	Type   int               `json:"type"`
	Msg    string            `json:"msg"`
	Text   string            `json:"text"`
	Fields []json.RawMessage `json:"fields"`
}

const (
	actCopyPath   = 100
	actSubstitute = 109
)

// parseSubstitutePaths extracts the store paths a nix internal-json log
// says will be (or are being) substituted.
func parseSubstitutePaths(log string) []string {
	var subs []string
	inFetchList := false
	for _, line := range strings.Split(log, "\n") {
		raw, ok := strings.CutPrefix(line, "@nix ")
		if !ok {
			continue
		}
		var ev nixLogEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			continue
		}
		switch ev.Action {
		case "msg":
			// Dry-run: "these N paths will be fetched…" then one
			// indented store path per message.
			m := strings.TrimRight(ev.Msg, ":")
			if strings.Contains(m, "will be fetched") {
				inFetchList = true
				continue
			}
			trimmed := strings.TrimSpace(ev.Msg)
			if inFetchList && strings.HasPrefix(trimmed, "/nix/store/") {
				subs = append(subs, cleanPath(trimmed))
				continue
			}
			if trimmed != "" && !strings.HasPrefix(trimmed, "/nix/store/") {
				inFetchList = false
			}
		case "start":
			if ev.Type != actCopyPath && ev.Type != actSubstitute {
				continue
			}
			if len(ev.Fields) == 0 {
				continue
			}
			var p string
			if err := json.Unmarshal(ev.Fields[0], &p); err != nil {
				continue
			}
			if strings.HasPrefix(p, "/nix/store/") {
				subs = append(subs, cleanPath(p))
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

// repairSubstitutes re-runs the dry-run substitute query — after a
// failed run it can name paths the pre-fetch didn't see (IFD, impure
// evaluation) — realises them, and repairs them. Returns true if a
// repair sweep ran clean and a retry is worthwhile. Best-effort like
// the pre-fetch: paths already local before the run are not revisited.
func repairSubstitutes(argv []string) bool {
	subs := willSubstituteFn(argv)
	realised := realiseFn(subs)
	if len(realised) == 0 {
		return false
	}
	return fixFn(realised) == 0
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
