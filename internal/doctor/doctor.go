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
	"github.com/machokeeper/machokeeper/internal/nixstore"
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

	// Group repairable findings by the store path that contains them, so
	// each store path is repaired on disk and then re-registered once.
	// Files outside any store path are repaired standalone.
	type group struct {
		storePath string // "" for a non-store file
		files     []*Finding
	}
	groups := map[string]*group{}
	var order []string
	for _, f := range findings {
		if !f.Repairable {
			continue
		}
		key := f.File
		sp, ok := nixstore.StorePathOf(f.File)
		if ok {
			key = sp
		}
		g := groups[key]
		if g == nil {
			g = &group{storePath: ""}
			if ok {
				g.storePath = sp
			}
			groups[key] = g
			order = append(order, key)
		}
		g.files = append(g.files, f)
	}

	journalPath := fmt.Sprintf("machokeeper-undo-%d.json", time.Now().Unix())
	var journal []journalEntry
	fixed := 0

	for _, key := range order {
		g := groups[key]

		// A rooted or referenced store path cannot be deleted, so it
		// cannot be re-registered via export/delete/import. Repairing
		// its bytes in place would leave the database NAR hash stale
		// (and `nix store verify --repair` would then regress it to the
		// broken cached copy). Refuse here; that case is the job of the
		// forthcoming `--fix-live`.
		if g.storePath != "" {
			blockers, err := storePathBlockers(g.storePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "fix: %s: %v\n", g.storePath, err)
				continue
			}
			if len(blockers) > 0 {
				fmt.Printf("SKIP    %s: in use (%s%s); repairing it in place would leave its recorded hash stale.\n",
					g.storePath, blockers[0], more(blockers))
				fmt.Println("        Rebuild it, or wait for `--fix-live` for GC-rooted paths (e.g. a login shell).")
				continue
			}
		}

		// Repair every broken file in the group on disk, hardlink-safely.
		var groupChanges []journalEntry
		ok := true
		for _, f := range g.files {
			changes, err := repairFileHardlinkSafe(f.File)
			if err != nil {
				fmt.Fprintf(os.Stderr, "fix: %s: %v\n", f.File, err)
				ok = false
				break
			}
			groupChanges = append(groupChanges, journalEntry{File: f.File, Time: time.Now(), Changes: changes})
			fmt.Printf("REPAIRED  %s  (%d slot(s))\n", f.File, len(changes))
		}
		if !ok {
			continue
		}

		// Re-register a store path so the database hash matches the
		// repaired bytes. Non-store files are done after the on-disk
		// write.
		if g.storePath != "" {
			if err := nixstore.Reregister(g.storePath); err != nil {
				fmt.Fprintf(os.Stderr, "fix: %s: %v\n", g.storePath, err)
				fmt.Fprintf(os.Stderr, "      (files were repaired on disk but the recorded hash is now stale; `nix store verify` will report it)\n")
				continue
			}
			fmt.Printf("re-registered %s\n", g.storePath)
		}
		journal = append(journal, groupChanges...)
		fixed += len(groupChanges)
	}

	if len(journal) > 0 {
		if j, err := json.MarshalIndent(journal, "", " "); err == nil {
			_ = os.WriteFile(journalPath, j, 0o644)
			fmt.Printf("\nundo journal: %s\n", journalPath)
		}
	}
	fmt.Printf("repaired %d file(s)\n", fixed)
	if fixed < repairable {
		return 1
	}
	return 0
}

func more(blockers []string) string {
	if len(blockers) > 1 {
		return fmt.Sprintf(" and %d more", len(blockers)-1)
	}
	return ""
}

// storePathBlockers returns GC roots and referrers that prevent deleting
// (and thus re-registering) a store path.
func storePathBlockers(storePath string) ([]string, error) {
	roots, err := nixstore.Roots(storePath)
	if err != nil {
		return nil, err
	}
	refs, err := nixstore.Referrers(storePath)
	if err != nil {
		return nil, err
	}
	return append(roots, refs...), nil
}

// repairFileHardlinkSafe repairs one signed Mach-O file. It writes the
// repaired bytes to a sibling temp file and renames it over the
// original, so a file shared by `auto-optimise-store` hardlinks is not
// corrupted through those other names — only this directory entry is
// repointed at a fresh inode. The repair is re-verified before the
// rename; only stale hash slots are ever changed.
func repairFileHardlinkSafe(path string) ([]engine.Change, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	changes, modified, err := engine.Repair(data, path)
	if err != nil {
		return nil, err
	}
	if !modified {
		return nil, fmt.Errorf("nothing to repair")
	}
	// Never trust our own repair: re-verify before writing.
	if engine.Check(data, path) {
		return nil, fmt.Errorf("still fails verification after repair; not writing")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".machokeeper-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmpName, st.Mode()); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	return changes, nil
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
