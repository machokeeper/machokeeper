package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/machokeeper/machokeeper/engine"
	"github.com/machokeeper/machokeeper/internal/machofixture"
)

// fakeStore records calls and lets a test declare which paths are
// "store paths" and which are rooted.
type fakeStore struct {
	storePaths map[string]string // file -> containing store path
	rooted     map[string]bool   // store path -> has blockers
	reregister []string
	reconcile  []string
	failReg    bool
}

func (f *fakeStore) StorePathOf(file string) (string, bool) {
	sp, ok := f.storePaths[file]
	return sp, ok
}
func (f *fakeStore) Blockers(sp string) ([]string, error) {
	if f.rooted[sp] {
		return []string{"/nix/var/nix/gcroots/x"}, nil
	}
	return nil, nil
}
func (f *fakeStore) Reregister(sp string) error {
	if f.failReg {
		return errReg
	}
	f.reregister = append(f.reregister, sp)
	return nil
}
func (f *fakeStore) ReconcileHash(sp string) error {
	f.reconcile = append(f.reconcile, sp)
	return nil
}

var errReg = &os.PathError{Op: "reregister", Path: "x", Err: syscall.EIO}

func withStore(t *testing.T, s storeBackend) {
	t.Helper()
	prev := store
	store = s
	t.Cleanup(func() { store = prev })
}

// writeFixture writes a fixture blob and asserts the engine sees it the
// way the test expects.
func writeFixture(t *testing.T, path string, blob []byte, wantKind engine.Kind, wantStale bool) {
	t.Helper()
	if got := engine.Detect(blob); got != wantKind {
		t.Fatalf("fixture Detect = %v, want %v", got, wantKind)
	}
	// engine.Check returns true when stale/unverifiable.
	if got := engine.Check(blob, path); got != wantStale {
		t.Fatalf("fixture Check(stale) = %v, want %v", got, wantStale)
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorDetectReportsRepairableAndUnrepairable(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	broken := filepath.Join(dir, "broken")
	cms := filepath.Join(dir, "cms")

	// A repaired (valid) fixture: repair a broken one first.
	valid := machofixture.Repairable(2)
	if _, _, err := engine.Repair(valid, "x"); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, good, valid, engine.AdHoc, false)
	writeFixture(t, broken, machofixture.Repairable(2), engine.AdHoc, true)
	writeFixture(t, cms, machofixture.CMS(2), engine.CMS, true)

	// Report only (no --fix): exit 2 because something is broken.
	if rc := Run([]string{"--quiet", dir}); rc != 2 {
		t.Errorf("report rc = %d, want 2", rc)
	}
}

func TestDoctorFixPlainFileRepairsAndJournals(t *testing.T) {
	withStore(t, &fakeStore{}) // no store paths -> plain-file path
	dir := t.TempDir()
	f := filepath.Join(dir, "broken")
	writeFixture(t, f, machofixture.Repairable(3), engine.AdHoc, true)
	origInode := inodeOf(t, f)

	cwd := chdir(t, dir) // journal lands in cwd for a plain file
	_ = cwd

	if rc := Run([]string{"--quiet", "--fix", f}); rc != 0 {
		t.Fatalf("fix rc = %d, want 0", rc)
	}
	// Repaired: engine.Check now reports valid.
	data, _ := os.ReadFile(f)
	if engine.Check(data, f) {
		t.Error("file still stale after --fix")
	}
	// Hardlink-safe: the directory entry points at a new inode.
	if inodeOf(t, f) == origInode {
		t.Error("inode unchanged; repair was not hardlink-safe (rename expected)")
	}
	// A journal was written and round-trips to the original bytes.
	assertJournalUndoes(t, dir, f)
}

func TestDoctorFixIsHardlinkSafe(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	f := filepath.Join(dir, "broken")
	link := filepath.Join(dir, "sharer")
	blob := machofixture.Repairable(2)
	writeFixture(t, f, blob, engine.AdHoc, true)
	if err := os.Link(f, link); err != nil {
		t.Skipf("hardlinks unsupported here: %v", err)
	}
	linkBefore, _ := os.ReadFile(link)

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	// The other name still holds the ORIGINAL (broken) bytes: repair
	// repointed f's entry, it did not write through the shared inode.
	linkAfter, _ := os.ReadFile(link)
	if string(linkAfter) != string(linkBefore) {
		t.Error("hardlink sharer was modified; auto-optimise-store safety violated")
	}
}

func TestDoctorFixStorePathReregisters(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-pkg")
	os.MkdirAll(filepath.Join(sp, "bin"), 0o755)
	f := filepath.Join(sp, "bin", "tool")
	fs := &fakeStore{storePaths: map[string]string{f: sp}}
	withStore(t, fs)
	writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if len(fs.reregister) != 1 || fs.reregister[0] != sp {
		t.Errorf("Reregister calls = %v, want [%s]", fs.reregister, sp)
	}
	if len(fs.reconcile) != 0 {
		t.Errorf("ReconcileHash should not be called for an unrooted path: %v", fs.reconcile)
	}
}

func TestDoctorFixRootedPathSkippedWithoutFixLive(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-fish")
	os.MkdirAll(filepath.Join(sp, "bin"), 0o755)
	f := filepath.Join(sp, "bin", "fish")
	fs := &fakeStore{
		storePaths: map[string]string{f: sp},
		rooted:     map[string]bool{sp: true},
	}
	withStore(t, fs)
	blob := machofixture.Repairable(2)
	writeFixture(t, f, blob, engine.AdHoc, true)

	chdir(t, dir)
	// --fix (not --fix-live) must refuse a rooted path and leave it
	// untouched: exit 1 (repairable but not repaired), no re-register.
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 2 {
		t.Errorf("rooted --fix rc = %d, want 2", rc)
	}
	if len(fs.reregister)+len(fs.reconcile) != 0 {
		t.Error("rooted path should not be re-registered under --fix")
	}
	after, _ := os.ReadFile(f)
	if !engine.Check(after, f) {
		t.Error("rooted path was modified under plain --fix; should have been skipped")
	}
}

func TestDoctorFixLiveRootedPathReconcilesHash(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-fish")
	os.MkdirAll(filepath.Join(sp, "bin"), 0o755)
	f := filepath.Join(sp, "bin", "fish")
	fs := &fakeStore{
		storePaths: map[string]string{f: sp},
		rooted:     map[string]bool{sp: true},
	}
	withStore(t, fs)
	writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix-live", f}); rc != 0 {
		t.Fatalf("--fix-live rc = %d, want 0", rc)
	}
	if len(fs.reconcile) != 1 || fs.reconcile[0] != sp {
		t.Errorf("ReconcileHash calls = %v, want [%s]", fs.reconcile, sp)
	}
	after, _ := os.ReadFile(f)
	if engine.Check(after, f) {
		t.Error("rooted path still stale after --fix-live")
	}
}

func TestDoctorNeverTouchesCMS(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	f := filepath.Join(dir, "devid")
	blob := machofixture.CMS(2)
	writeFixture(t, f, blob, engine.CMS, true)
	before, _ := os.ReadFile(f)

	chdir(t, dir)
	// --fix over a CMS-only file: nothing repairable, exit 2, bytes intact.
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 2 {
		t.Errorf("rc = %d, want 2 (nothing repairable)", rc)
	}
	after, _ := os.ReadFile(f)
	if string(after) != string(before) {
		t.Error("CMS file was modified")
	}
}

func TestCheckExitContract(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken")
	writeFixture(t, broken, machofixture.Repairable(2), engine.AdHoc, true)
	if rc := Check([]string{broken}); rc != 2 {
		t.Errorf("check(broken) = %d, want 2", rc)
	}

	good := machofixture.Repairable(2)
	engine.Repair(good, "x")
	gf := filepath.Join(dir, "good")
	os.WriteFile(gf, good, 0o644)
	if rc := Check([]string{gf}); rc != 0 {
		t.Errorf("check(good) = %d, want 0", rc)
	}
}

// --- helpers ---

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func chdir(t *testing.T, dir string) string {
	t.Helper()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(prev) })
	return prev
}

func assertJournalUndoes(t *testing.T, dir, repaired string) {
	t.Helper()
	entries, _ := filepath.Glob(filepath.Join(dir, "machokeeper-undo-*.json"))
	if len(entries) == 0 {
		t.Fatal("no undo journal written")
	}
	var j []journalEntry
	raw, _ := os.ReadFile(entries[0])
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	if len(j) == 0 || len(j[0].Changes) == 0 {
		t.Fatal("journal has no changes recorded")
	}
	// Apply the journal's old bytes back and confirm the file becomes
	// stale again (byte-exact reversal of a slot-only repair).
	data, _ := os.ReadFile(repaired)
	for _, e := range j {
		for _, c := range e.Changes {
			copy(data[c.Offset:], c.Old)
		}
	}
	if !engine.Check(data, repaired) {
		t.Error("undo journal did not restore the original (stale) bytes")
	}
}

func TestWalkParallelFindsAllBroken(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	// A tree of many broken files plus decoys the scan must ignore.
	const nBroken = 40
	for i := 0; i < nBroken; i++ {
		sub := filepath.Join(dir, "d", string(rune('a'+i%20)))
		os.MkdirAll(sub, 0o755)
		os.WriteFile(filepath.Join(sub, fmtInt(i)+".dylib"), machofixture.Repairable(2), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "not-macho"), []byte("hello world not a binary"), 0o644)
	valid := machofixture.Repairable(2)
	engine.Repair(valid, "x")
	os.WriteFile(filepath.Join(dir, "valid.dylib"), valid, 0o644)

	var count int
	if err := walkParallel(dir, func(*Finding) { count++ }); err != nil {
		t.Fatal(err)
	}
	if count != nBroken {
		t.Errorf("walkParallel found %d broken, want %d", count, nBroken)
	}
}

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
