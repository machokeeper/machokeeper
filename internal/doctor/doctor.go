// Package doctor implements detect/report/repair over files, store
// paths, or the whole store. Detection is read-only; repair is opt-in
// via --fix and journaled for byte-exact undo.
package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/machokeeper/machokeeper/engine"
	"github.com/machokeeper/machokeeper/internal/nixstore"
)

// maxMachOFileSize is the largest Mach-O file whose signature can be
// verified: the CodeDirectory codeLimit field is 32 bits, so a
// signature over more than 4 GiB needs the codeLimit64 variant this
// engine does not support — such a file is genuinely unverifiable.
// Scanning also never loads a file this large into memory (the parallel
// store scan would risk OOM). A Mach-O-magic file above the bound is
// reported unverifiable without being read (fail closed). Overridable
// via MACHOKEEPER_MAX_FILE_SIZE (bytes) so tests exercise the oversized
// path without gigabyte fixtures. Mirrors nix's maxMachOFileSize.
func maxMachOFileSize() int64 {
	return sizeBoundFromEnv("MACHOKEEPER_MAX_FILE_SIZE", 4<<30)
}

// maxMachOInMemorySize is the largest file scanFile will heap-read when
// it cannot be memory-mapped. Checking is cheap at any size via mmap;
// an unbounded fallback read is not, so a file above this bound that
// cannot be mapped is reported unverifiable (fail closed) rather than
// loaded. Overridable via MACHOKEEPER_MAX_IN_MEMORY_SIZE.
func maxMachOInMemorySize() int64 {
	return sizeBoundFromEnv("MACHOKEEPER_MAX_IN_MEMORY_SIZE", 512<<20)
}

func sizeBoundFromEnv(envVar string, dflt int64) int64 {
	if v := os.Getenv(envVar); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return dflt
}

// storeBackend is the set of Nix store operations repair needs. It is
// an interface so tests can drive the full fix / fix-live flow without a
// live daemon; the default implementation calls internal/nixstore.
type storeBackend interface {
	StorePathOf(file string) (string, bool)
	Blockers(storePath string) ([]string, error)
	ReconcileHash(storePath string) error
	IsContentAddressed(storePath string) (bool, error)
}

type realStore struct{}

func (realStore) StorePathOf(f string) (string, bool) { return nixstore.StorePathOf(f) }
func (realStore) Blockers(p string) ([]string, error) { return storePathBlockers(p) }
func (realStore) ReconcileHash(p string) error        { return reconcileHash(p) }
func (realStore) IsContentAddressed(p string) (bool, error) {
	return nixstore.IsContentAddressed(p)
}

// store is the backend used by Run; tests replace it.
var store storeBackend = realStore{}

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
	defer func() { _ = f.Close() }()
	peek := make([]byte, 4)
	if _, err := io.ReadFull(f, peek); err != nil || !engine.HasMachOMagic(peek) {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	size := fi.Size()

	// A Mach-O-magic file too large for its signature to be verified —
	// or unmappable and too large to load — is reported unverifiable
	// without being read. It could carry a signature the rewrite would
	// invalidate, so fail closed rather than silently pass it, and never
	// risk OOM loading it under the parallel scan.
	if size > maxMachOFileSize() {
		return oversizedFinding(path, size)
	}
	data, unmap, err := readForScan(f, size)
	if err != nil {
		if err == errTooLargeToLoad {
			return oversizedFinding(path, size)
		}
		return nil
	}
	defer unmap()

	kind := engine.Detect(data)
	if kind == engine.None {
		return nil
	}
	if !engine.Check(data, path) {
		return nil // signed and valid
	}
	// Repairable means a repair would actually leave the file valid —
	// proven by a trial repair on the in-memory copy, not inferred from
	// the signature class. An ad-hoc file whose signature is stale
	// because it is UNVERIFIABLE (malformed CodeDirectory, unsupported
	// hash type) has nothing repair can rewrite and must be reported
	// unrepairable, not queued for a fix that will no-op.
	repairable := false
	if kind == engine.AdHoc {
		trial := append([]byte(nil), data...)
		if _, modified, err := engine.Repair(trial, path); err == nil && modified && !engine.Check(trial, path) {
			repairable = true
		}
	}
	class := kind.String()
	if kind == engine.AdHoc && !repairable {
		class = "ad-hoc (unverifiable)"
	}
	return &Finding{
		File:       path,
		Kind:       kind,
		Class:      class,
		Repairable: repairable,
	}
}

// errTooLargeToLoad: the file cannot be mapped and is larger than
// maxMachOInMemorySize, so readForScan refuses to heap-load it.
var errTooLargeToLoad = fmt.Errorf("file too large to load")

// readForScan returns the bytes to inspect: a read-only mmap where
// possible (no heap cost — detection reads a few scattered KiB), else a
// bounded heap read. unmap must be called when the bytes are done.
func readForScan(f *os.File, size int64) (data []byte, unmap func(), err error) {
	if size == 0 {
		return nil, func() {}, nil
	}
	if mapped, munmap, err := mmapRead(f, size); err == nil {
		return mapped, munmap, nil
	}
	if size > maxMachOInMemorySize() {
		return nil, nil, errTooLargeToLoad
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		return nil, nil, err
	}
	return b, func() {}, nil
}

// oversizedFinding reports a Mach-O file that could not be verified
// because it exceeds the size bounds. Unrepairable and fail-closed: the
// check exit contract treats it as stale so a broken oversized binary
// is never silently accepted.
func oversizedFinding(path string, size int64) *Finding {
	return &Finding{
		File:       path,
		Kind:       engine.None,
		Class:      fmt.Sprintf("unverifiable: %d bytes exceeds the verifiable size bound", size),
		Repairable: false,
	}
}

// walkParallel scans a file or directory tree (symlinks never
// followed) with the per-file scan fanned out over a worker pool: a
// whole-store scan is dominated by reading and hashing file contents,
// which parallelises cleanly. Directory traversal stays
// single-threaded; findings are delivered from a single goroutine, so
// the visit callback needs no locking.
func walkParallel(root string, visit func(*Finding)) error {
	workers := runtime.NumCPU()
	files := make(chan string, workers*4)
	results := make(chan *Finding, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range files {
				if f := scanFile(p); f != nil {
					results <- f
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var walkErr error
	go func() {
		defer close(files)
		info, err := os.Lstat(root)
		if err != nil {
			walkErr = err
			return
		}
		if info.Mode().IsRegular() {
			files <- root
			return
		}
		if !info.IsDir() {
			return
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries, keep walking
			}
			if d.Type().IsRegular() {
				files <- p
			}
			return nil
		})
	}()

	for f := range results {
		visit(f)
	}
	return walkErr
}

// Run implements `machokeeper doctor`.
func Run(args []string) int {
	fix := false
	fixLive := false
	scan := false
	quiet := false
	jsonOut := false
	var paths []string
	for _, a := range args {
		switch a {
		case "--fix":
			fix = true
		case "--fix-live":
			fix = true
			fixLive = true
		case "--scan":
			scan = true
		case "--quiet":
			quiet = true
		case "--json":
			jsonOut = true
			quiet = true
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

	say := func(format string, a ...any) {
		if !quiet {
			fmt.Printf(format, a...)
		}
	}

	var findings []*Finding
	for _, p := range paths {
		if err := walkParallel(p, func(f *Finding) { findings = append(findings, f) }); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %s: %v\n", p, err)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].File < findings[j].File })

	if jsonOut && !fix {
		out, _ := json.MarshalIndent(findings, "", "  ")
		fmt.Println(string(out))
		if len(findings) == 0 {
			return 0
		}
		return 2
	}

	if len(findings) == 0 {
		say("no broken Mach-O signatures found (of the ad-hoc/page-hash class)\n")
		return 0
	}

	repairable := 0
	for _, f := range findings {
		status := "unrepairable (" + f.Class + ")"
		if f.Repairable {
			status = "repairable"
			repairable++
		}
		say("BROKEN  %s  [%s]\n", f.File, status)
	}
	say("\n%d broken file(s); %d repairable\n", len(findings), repairable)

	if !fix {
		if repairable > 0 {
			say("run again with --fix to repair (writes an undo journal)\n")
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
		sp, ok := store.StorePathOf(f.File)
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

	journalPath := journalFile()
	var journal []journalEntry
	fixed := 0

	// The repair phase writes store files and reconciles their DB hash.
	// Hold nix's GC lock shared for its duration when any store path is
	// involved, so a concurrent `nix-store --gc` can't collect a path
	// mid-repair — the same shared lock the daemon takes for its own
	// store writes. Plain-file repairs (no store path) need no lock.
	anyStorePath := false
	for _, g := range groups {
		if g.storePath != "" {
			anyStorePath = true
			break
		}
	}

	runRepairs := func() error {
		for _, key := range order {
			g := groups[key]

			// A rooted or referenced store path is live — a login shell, a
			// current system generation. Repairing something in use needs
			// the operator's explicit consent: without --fix-live, refuse.
			// (The hash reconciliation below works for rooted and unrooted
			// paths alike; the distinction is consent, not mechanism.)
			reconcile := g.storePath != ""

			// A content-addressed path's name IS a function of its bytes:
			// repairing it would break the content address. Refusal class
			// (THREAT-MODEL); no --fix variant overrides it. A failed query
			// also refuses — unknown must never be treated as repairable.
			if g.storePath != "" {
				ca, err := store.IsContentAddressed(g.storePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "fix: %s: cannot determine if content-addressed, refusing: %v\n", g.storePath, err)
					continue
				}
				if ca {
					say("SKIP    %s: content-addressed; repairing would break its content address (see THREAT-MODEL.md)\n", g.storePath)
					continue
				}
			}

			if g.storePath != "" && !fixLive {
				blockers, err := store.Blockers(g.storePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "fix: %s: %v\n", g.storePath, err)
					continue
				}
				if len(blockers) > 0 {
					say("SKIP    %s: in use (%s%s); repairing it in place would leave its recorded hash stale.\n",
						g.storePath, blockers[0], more(blockers))
					say("        Re-run with --fix-live to repair a GC-rooted path (e.g. a login shell) and reconcile its hash.\n")
					continue
				}
			}

			// Repair every broken file in the group on disk, hardlink-safely.
			// Each file's changes go into the journal the moment its rename
			// lands: a failure later in the group (or at re-registration)
			// must not lose the undo records of bytes already on disk.
			repairedInGroup := 0
			ok := true
			for _, f := range g.files {
				changes, err := repairFileHardlinkSafe(f.File)
				if err != nil {
					fmt.Fprintf(os.Stderr, "fix: %s: %v\n", f.File, err)
					ok = false
					break
				}
				journal = append(journal, journalEntry{File: f.File, Time: time.Now(), Changes: changes})
				repairedInGroup++
				say("REPAIRED  %s  (%d slot(s))\n", f.File, len(changes))
			}
			if !ok {
				continue
			}

			// Make the database hash row match the repaired bytes:
			// re-register validity with the recomputed NAR hash, in place.
			// (export/delete/import is NOT usable here: `nix-store
			// --export` verifies the recorded hash before streaming, so it
			// always fails on a just-repaired path.)
			if reconcile {
				if err := store.ReconcileHash(g.storePath); err != nil {
					fmt.Fprintf(os.Stderr, "fix: %s: %v\n", g.storePath, err)
					fmt.Fprintf(os.Stderr, "      (files were repaired on disk but the recorded hash is now stale; `nix store verify` will report it)\n")
					continue
				}
				say("re-registered %s\n", g.storePath)
			}
			fixed += repairedInGroup
		}
		return nil
	}

	if anyStorePath {
		_ = withGCLock(runRepairs)
	} else {
		_ = runRepairs()
	}

	if len(journal) > 0 {
		if j, err := json.MarshalIndent(journal, "", " "); err == nil {
			if werr := os.WriteFile(journalPath, j, 0o600); werr != nil {
				fmt.Fprintf(os.Stderr, "fix: writing undo journal %s: %v\n", journalPath, werr)
			} else {
				say("\nundo journal: %s\n", journalPath)
			}
		}
	}
	say("repaired %d file(s)\n", fixed)
	// Exit 0 only when nothing broken remains. If any broken file was
	// not repaired — unrepairable (CMS/CA), a rooted path skipped
	// without --fix-live, or a repair error — something in the store is
	// still broken, so report exit 2, the same "stale" signal `check`
	// and report-mode use.
	if fixed < len(findings) {
		return 2
	}
	return 0
}

// journalDir is the preferred undo-journal location; tests point it at
// a TempDir so they never probe (or pollute) the real /nix/var.
var journalDir = "/nix/var/machokeeper"

// journalFile returns a writable path for the undo journal: a
// timestamped file under journalDir when writable (the module runs
// there), else the current directory (interactive doctor use).
func journalFile() string {
	name := fmt.Sprintf("machokeeper-undo-%d.json", time.Now().Unix())
	dir := journalDir
	if err := os.MkdirAll(dir, 0o750); err == nil {
		if f, err := os.CreateTemp(dir, ".probe-"); err == nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return filepath.Join(dir, name)
		}
	}
	return name
}

func more(blockers []string) string {
	if len(blockers) > 1 {
		return fmt.Sprintf(" and %d more", len(blockers)-1)
	}
	return ""
}

// reconcileHash updates the database NAR hash of an already-repaired
// store path in place (no delete), so it works on GC-rooted paths.
// Dumps the repaired NAR, computes its hash, and re-registers validity
// with the path's existing deriver and references.
func reconcileHash(storePath string) error {
	nar, err := nixstore.DumpNAR(storePath)
	if err != nil {
		return err
	}
	deriver, refs, err := nixstore.PathInfo(storePath)
	if err != nil {
		return err
	}
	return nixstore.RegisterValidity(storePath, deriver, nixstore.NarHash(nar), int64(len(nar)), refs)
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
	if err := replaceFile(path, data); err != nil {
		return nil, err
	}
	return changes, nil
}

// replaceFile writes data to a sibling temp file and renames it over
// path, preserving the original mode — the hardlink-safe write both
// repair and undo use.
func replaceFile(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".machokeeper-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, st.Mode()); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Undo implements `machokeeper undo <journal.json>`: restore the exact
// pre-repair bytes recorded by a --fix run. Each file is verified to
// still hold the repaired bytes at every journaled offset before any
// write — a file that changed since the repair is refused, never
// spliced. The write is temp+rename, the same hardlink-safe route
// repair takes. Note the store DB hash is NOT reconciled here; undo
// restores bytes so `nix store verify --repair` can take over.
func Undo(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "undo: usage: machokeeper undo <machokeeper-undo-*.json>")
		return 1
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "undo: %v\n", err)
		return 1
	}
	var journal []journalEntry
	if err := json.Unmarshal(raw, &journal); err != nil {
		fmt.Fprintf(os.Stderr, "undo: %s: %v\n", args[0], err)
		return 1
	}
	rc := 0
	for _, e := range journal {
		if err := undoFile(e); err != nil {
			fmt.Fprintf(os.Stderr, "undo: %s: %v\n", e.File, err)
			rc = 1
			continue
		}
		fmt.Printf("RESTORED  %s  (%d slot(s))\n", e.File, len(e.Changes))
	}
	return rc
}

// undoFile restores one journal entry, refusing unless every journaled
// offset still holds the repaired bytes. Changes are un-applied in
// reverse journal order — the repair wrote them forward, so if two
// entries ever overlap, only last-undone-first restores the original
// bytes exactly. Bounds are validated up front so a refusal never
// leaves a half-restored buffer.
func undoFile(e journalEntry) error {
	// Same discipline as the scan path: only regular files. A journaled
	// path that became a symlink since the repair is refused, not
	// followed.
	st, err := os.Lstat(e.File)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (mode %v); refusing", st.Mode())
	}
	data, err := os.ReadFile(e.File)
	if err != nil {
		return err
	}
	for _, c := range e.Changes {
		// Subtraction form: journals are user-editable JSON, so an
		// Offset near MaxInt64 must refuse cleanly, not wrap the sum.
		if c.Offset < 0 || int64(len(c.Old)) > int64(len(data)) || c.Offset > int64(len(data))-int64(len(c.Old)) {
			return fmt.Errorf("journal offset %d out of bounds (file is %d bytes)", c.Offset, len(data))
		}
	}
	warned := false
	for i := len(e.Changes) - 1; i >= 0; i-- {
		c := e.Changes[i]
		end := c.Offset + int64(len(c.Old))
		if len(c.New) == 0 {
			// A journal from before the New field existed: the
			// changed-since-repair verification cannot run. Proceed —
			// refusing would strand every pre-upgrade journal — but say
			// so once.
			if !warned {
				fmt.Fprintf(os.Stderr, "undo: %s: journal has no repaired-bytes record; restoring without changed-since-repair verification\n", e.File)
				warned = true
			}
		} else if !bytesEq(data[c.Offset:end], c.New) {
			return fmt.Errorf("slot at offset %d does not hold the repaired bytes; file changed since repair, refusing", c.Offset)
		}
		copy(data[c.Offset:], c.Old)
	}
	return replaceFile(e.File, data)
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
		if err := walkParallel(p, func(f *Finding) { stale++ }); err != nil {
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
