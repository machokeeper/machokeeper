// Package doctor implements detect/report/repair over files, store
// paths, or the whole store. Detection is read-only; repair is opt-in
// via --fix and journaled for byte-exact undo.
package doctor

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/machokeeper/machokeeper/engine"
)

// A Finding is one broken (or unrepairable) signed Mach-O file.
type Finding struct {
	File string      `json:"file"`
	Kind engine.Kind `json:"-"`
	// Class is the human-readable signature class.
	Class string `json:"class"`
	// Repairable: ad-hoc signatures only.
	Repairable bool `json:"repairable"`
}

// journalEntry records one repaired file for undo.
type journalEntry struct {
	File    string          `json:"file"`
	Time    time.Time       `json:"time"`
	Changes []engine.Change `json:"changes"`
}

// scanFile inspects one regular file; returns nil if healthy or not a
// signed Mach-O.
func scanFile(path string) *Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	peek := make([]byte, 4)
	if n, _ := f.Read(peek); n < 4 || !engine.HasMachOMagic(peek) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	kind := engine.Detect(data)
	if kind == engine.None {
		return nil
	}
	if !engine.Check(data, path) {
		return nil // signed and valid
	}
	return &Finding{
		File:       path,
		Kind:       kind,
		Class:      kind.String(),
		Repairable: kind == engine.AdHoc,
	}
}

// walk scans a file or directory tree (symlinks never followed).
func walk(root string, visit func(*Finding)) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode().IsRegular() {
		if f := scanFile(root); f != nil {
			visit(f)
		}
		return nil
	}
	if !info.IsDir() {
		return nil
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
		}
		if d.Type().IsRegular() {
			if f := scanFile(p); f != nil {
				visit(f)
			}
		}
		return nil
	})
}

// Run implements `machokeeper doctor`.
func Run(args []string) int {
	fix := false
	scan := false
	var paths []string
	for _, a := range args {
		switch a {
		case "--fix":
			fix = true
		case "--scan":
			scan = true
		default:
			paths = append(paths, a)
		}
	}
	if scan {
		paths = append(paths, "/nix/store")
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "doctor: no paths given (use --scan for the whole store)")
		return 1
	}

	var findings []*Finding
	for _, p := range paths {
		if err := walk(p, func(f *Finding) { findings = append(findings, f) }); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %s: %v\n", p, err)
		}
	}

	if len(findings) == 0 {
		fmt.Println("no broken Mach-O signatures found (of the ad-hoc/page-hash class)")
		return 0
	}

	repairable := 0
	for _, f := range findings {
		status := "unrepairable (" + f.Class + ")"
		if f.Repairable {
			status = "repairable"
			repairable++
		}
		fmt.Printf("BROKEN  %s  [%s]\n", f.File, status)
	}
	fmt.Printf("\n%d broken file(s); %d repairable\n", len(findings), repairable)

	if !fix {
		if repairable > 0 {
			fmt.Println("run again with --fix to repair (writes an undo journal)")
		}
		return 2
	}

	journalPath := fmt.Sprintf("machokeeper-undo-%d.json", time.Now().Unix())
	var journal []journalEntry
	fixed := 0
	for _, f := range findings {
		if !f.Repairable {
			continue
		}
		data, err := os.ReadFile(f.File)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fix: %s: %v\n", f.File, err)
			continue
		}
		changes, modified, err := engine.Repair(data, f.File)
		if err != nil || !modified {
			fmt.Fprintf(os.Stderr, "fix: %s: %v\n", f.File, err)
			continue
		}
		// Never trust our own repair: re-verify before writing.
		if engine.Check(data, f.File) {
			fmt.Fprintf(os.Stderr, "fix: %s: still fails verification after repair; not writing\n", f.File)
			continue
		}
		st, err := os.Stat(f.File)
		if err != nil {
			continue
		}
		if err := writeInPlace(f.File, data, st); err != nil {
			fmt.Fprintf(os.Stderr, "fix: %s: %v (root needed for store paths?)\n", f.File, err)
			continue
		}
		journal = append(journal, journalEntry{File: f.File, Time: time.Now(), Changes: changes})
		fmt.Printf("REPAIRED  %s  (%d slot(s))\n", f.File, len(changes))
		fixed++
	}
	if len(journal) > 0 {
		if j, err := json.MarshalIndent(journal, "", " "); err == nil {
			_ = os.WriteFile(journalPath, j, 0o644)
			fmt.Printf("\nundo journal: %s\n", journalPath)
		}
	}
	fmt.Printf("repaired %d of %d repairable file(s)\n", fixed, repairable)
	if fixed < repairable {
		return 1
	}
	return 0
}

// writeInPlace writes repaired bytes preserving mode. Store files are
// read-only; add owner-write transiently and restore.
//
// NOTE (M2): direct in-place writing is only safe for non-optimised,
// non-shared files. The store-path-aware fix path (export → repair →
// import, hardlink-safe) lands with the nix integration; this is the
// plain-file path used for files outside the store and for tests.
func writeInPlace(path string, data []byte, st os.FileInfo) error {
	mode := st.Mode()
	if mode&0o200 == 0 {
		if err := os.Chmod(path, mode|0o200); err != nil {
			return err
		}
		defer os.Chmod(path, mode)
	}
	return os.WriteFile(path, data, mode)
}

// Check implements `machokeeper check`: exit 0 all valid, 2 stale or
// unverifiable, 1 usage/IO error. Mirrors the exit contract of
// `nix __fixup-macho --check` from the #15638 branch.
func Check(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "check: no paths given")
		return 1
	}
	stale := 0
	for _, p := range args {
		if err := walk(p, func(f *Finding) { stale++ }); err != nil {
			fmt.Fprintf(os.Stderr, "check: %s: %v\n", p, err)
			return 1
		}
	}
	if stale > 0 {
		fmt.Fprintf(os.Stderr, "%d file(s) with stale or unverifiable signatures\n", stale)
		return 2
	}
	return 0
}
