// Package nixstore wraps the stock `nix-store` CLI operations machokeeper
// needs, so repair uses only documented plumbing — no daemon patch, no
// direct database access.
package nixstore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StorePathOf returns the top-level store path containing file `p`
// (…/<hash>-<name>), and true, or ("", false) if `p` is not under a
// store directory. The store dir is taken from NIX_STORE_DIR (tests) or
// defaults to /nix/store.
func StorePathOf(p string) (string, bool) {
	storeDir := os.Getenv("NIX_STORE_DIR")
	if storeDir == "" {
		storeDir = "/nix/store"
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(storeDir, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	first := rel
	if i := strings.IndexByte(rel, filepath.Separator); i >= 0 {
		first = rel[:i]
	}
	if first == "" || first == "." {
		return "", false
	}
	return filepath.Join(storeDir, first), true
}

// Roots returns the GC roots holding `storePath` alive. A non-empty
// result means the path cannot be deleted (and so cannot be
// re-registered via export/delete/import); such paths need the
// in-place `--fix-live` route instead.
func Roots(storePath string) ([]string, error) {
	out, err := exec.Command("nix-store", "--query", "--roots", storePath).Output()
	if err != nil {
		return nil, fmt.Errorf("querying roots of %s: %w", storePath, err)
	}
	var roots []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			roots = append(roots, line)
		}
	}
	return roots, nil
}

// Referrers returns store paths that reference `storePath`. Like a GC
// root, a referrer blocks deletion.
func Referrers(storePath string) ([]string, error) {
	out, err := exec.Command("nix-store", "--query", "--referrers", storePath).Output()
	if err != nil {
		return nil, fmt.Errorf("querying referrers of %s: %w", storePath, err)
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" && line != storePath {
			refs = append(refs, line)
		}
	}
	return refs, nil
}

// Reregister re-registers `storePath` from its current on-disk contents
// via export → delete → import, so the database NAR hash matches the
// repaired bytes. The path keeps its name (input-addressed paths do not
// depend on their contents). Fails if the path is rooted or referenced;
// callers must check Roots/Referrers first.
func Reregister(storePath string) error {
	tmp, err := os.CreateTemp("", "machokeeper-export-*.nar")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	// export: streams the NAR from disk (repaired contents) plus the
	// path's metadata; the NAR hash is recomputed on import.
	exp := exec.Command("nix-store", "--export", storePath)
	exp.Stdout = tmp
	exp.Stderr = os.Stderr
	if err := exp.Run(); err != nil {
		return fmt.Errorf("exporting %s: %w", storePath, err)
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}

	if out, err := exec.Command("nix-store", "--delete", storePath).CombinedOutput(); err != nil {
		return fmt.Errorf("deleting %s (rooted or referenced?): %w: %s", storePath, err, strings.TrimSpace(string(out)))
	}

	imp := exec.Command("nix-store", "--import")
	imp.Stdin = tmp
	imp.Stderr = os.Stderr
	if err := imp.Run(); err != nil {
		return fmt.Errorf("re-importing %s: %w", storePath, err)
	}
	return nil
}
