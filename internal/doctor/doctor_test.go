package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/machokeeper/machokeeper/engine"
	"github.com/machokeeper/machokeeper/internal/machofixture"
)

// fakeStore records calls and lets a test declare which paths are
// "store paths" and which are rooted.
type fakeStore struct {
	storePaths map[string]string // file -> containing store path
	rooted     map[string]bool   // store path -> has blockers
	ca         map[string]bool   // store path -> content-addressed
	failCA     bool              // IsContentAddressed returns an error
	reconcile  []string          // ReconcileHash calls
	failReg    bool              // ReconcileHash returns an error
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
func (f *fakeStore) ReconcileHash(sp string) error {
	if f.failReg {
		return errReg
	}
	f.reconcile = append(f.reconcile, sp)
	return nil
}
func (f *fakeStore) IsContentAddressed(sp string) (bool, error) {
	if f.failCA {
		return false, errReg
	}
	return f.ca[sp], nil
}

var errReg = &os.PathError{Op: "reregister", Path: "x", Err: syscall.EIO}

func withStore(t *testing.T, s storeBackend) {
	t.Helper()
	prev := store
	store = s
	// Keep journal probing away from the real /nix/var: point the
	// preferred dir below a regular FILE so MkdirAll fails and the cwd
	// fallback (what these tests assert on) is always taken.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	prevDir := journalDir
	journalDir = filepath.Join(blocker, "sub")
	// Never flock the real /nix/var/nix/gc.lock from a unit test: point
	// the GC lock at a per-test temp file so the coordination code path
	// runs against a harmless target.
	prevLock := gcLockPath
	lock := filepath.Join(t.TempDir(), "gc.lock")
	_ = os.WriteFile(lock, nil, 0o644)
	gcLockPath = lock
	t.Cleanup(func() { store = prev; journalDir = prevDir; gcLockPath = prevLock })
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

// TestPlanFileRepairVerifiesBeforeWrite pins the repair FSM: planFileRepair
// re-verifies in memory and yields a verifiedRepair token while writing
// NOTHING to disk; only writeRepair (which requires the token) commits. So an
// unverified repair can never reach disk — it is unrepresentable, not merely
// guarded by call ordering.
func TestPlanFileRepairVerifiesBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "broken")
	writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)

	// Plan: yields a verified token with changes, but does NOT touch disk.
	vr, err := planFileRepair(f)
	if err != nil {
		t.Fatalf("planFileRepair: %v", err)
	}
	if len(vr.changes) == 0 {
		t.Fatal("planFileRepair returned no changes for a repairable file")
	}
	if onDisk, _ := os.ReadFile(f); !engine.Check(onDisk, f) {
		t.Fatal("planFileRepair wrote to disk (file no longer stale); it must decide, not apply")
	}

	// Apply: only writeRepair commits the verified bytes.
	if err := writeRepair(vr); err != nil {
		t.Fatalf("writeRepair: %v", err)
	}
	if onDisk, _ := os.ReadFile(f); engine.Check(onDisk, f) {
		t.Fatal("writeRepair did not leave the file valid")
	}

	// A now-valid file yields no token (and thus no possible write).
	if _, err := planFileRepair(f); err == nil {
		t.Fatal("planFileRepair on a valid file returned a token; want an error (nothing to repair)")
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
	if len(fs.reconcile) != 1 || fs.reconcile[0] != sp {
		t.Errorf("ReconcileHash calls = %v, want [%s]", fs.reconcile, sp)
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
	if len(fs.reconcile) != 0 {
		t.Error("rooted path should not be reconciled under --fix")
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
	// Apply the journal's old bytes back (entries for THIS file only —
	// a multi-file journal's other offsets belong to other files) and
	// confirm the file becomes stale again.
	found := false
	data, _ := os.ReadFile(repaired)
	for _, e := range j {
		if e.File != repaired {
			continue
		}
		found = true
		for _, c := range e.Changes {
			copy(data[c.Offset:], c.Old)
		}
	}
	if !found {
		t.Fatalf("journal has no entry for %s", repaired)
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
	if err := walkParallel(dir, scanConfig{}, func(*Finding) { count++ }); err != nil {
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

func TestDoctorFixPartialGroupFailureStillJournals(t *testing.T) {
	// Two repairable files in ONE store path; the second one's directory
	// is read-only, so its repair fails after the first file has already
	// been renamed into place. The already-repaired file must still get
	// an undo journal entry — a mid-group failure must not discard the
	// records of bytes that are already on disk.
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-pkg")
	binDir := filepath.Join(sp, "bin")
	libDir := filepath.Join(sp, "libexec")
	os.MkdirAll(binDir, 0o755)
	os.MkdirAll(libDir, 0o755)
	a := filepath.Join(binDir, "a-tool")
	b := filepath.Join(libDir, "b-tool")
	fs := &fakeStore{storePaths: map[string]string{a: sp, b: sp}}
	withStore(t, fs)
	writeFixture(t, a, machofixture.Repairable(2), engine.AdHoc, true)
	writeFixture(t, b, machofixture.Repairable(2), engine.AdHoc, true)
	if err := os.Chmod(libDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(libDir, 0o755) })

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", a, b}); rc != 2 {
		t.Errorf("rc = %d, want 2 (b was not repaired)", rc)
	}
	dataA, _ := os.ReadFile(a)
	if engine.Check(dataA, a) {
		t.Fatal("a should have been repaired before b failed")
	}
	// a's on-disk bytes changed, so the journal must record them.
	assertJournalUndoes(t, dir, a)
}

func TestDoctorFixJournalsWhenReregisterFails(t *testing.T) {
	// Re-registration fails after the file was repaired and renamed into
	// place: the byte changes are on disk, so the journal must record
	// them even though the group did not complete.
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-pkg")
	os.MkdirAll(filepath.Join(sp, "bin"), 0o755)
	f := filepath.Join(sp, "bin", "tool")
	fs := &fakeStore{storePaths: map[string]string{f: sp}, failReg: true}
	withStore(t, fs)
	writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 2 {
		t.Errorf("rc = %d, want 2 (repaired on disk but not re-registered)", rc)
	}
	data, _ := os.ReadFile(f)
	if engine.Check(data, f) {
		t.Fatal("file should have been repaired on disk")
	}
	assertJournalUndoes(t, dir, f)
}

func TestUndoRestoresOriginalBytes(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	f := filepath.Join(dir, "broken")
	blob := machofixture.Repairable(3)
	original := append([]byte(nil), blob...)
	writeFixture(t, f, blob, engine.AdHoc, true)

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 0 {
		t.Fatalf("fix rc = %d", rc)
	}
	journals, _ := filepath.Glob(filepath.Join(dir, "machokeeper-undo-*.json"))
	if len(journals) != 1 {
		t.Fatalf("journals = %v, want exactly 1", journals)
	}
	repairedInode := inodeOf(t, f)

	if rc := Undo([]string{journals[0]}); rc != 0 {
		t.Fatalf("undo rc = %d", rc)
	}
	after, _ := os.ReadFile(f)
	if string(after) != string(original) {
		t.Error("undo did not restore the original bytes exactly")
	}
	// Hardlink-safe like repair: a fresh inode, not an in-place write.
	if inodeOf(t, f) == repairedInode {
		t.Error("undo wrote in place; expected temp+rename")
	}
}

func TestUndoRefusesWhenFileChangedSinceRepair(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	f := filepath.Join(dir, "broken")
	writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 0 {
		t.Fatalf("fix rc = %d", rc)
	}
	journals, _ := filepath.Glob(filepath.Join(dir, "machokeeper-undo-*.json"))
	// The file was replaced since the repair: undo must refuse rather
	// than blindly splice stale bytes into unrelated content.
	if err := os.WriteFile(f, []byte("something else entirely"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := Undo([]string{journals[0]}); rc == 0 {
		t.Fatal("undo of a changed file must fail")
	}
	after, _ := os.ReadFile(f)
	if string(after) != "something else entirely" {
		t.Error("undo modified a file it should have refused")
	}
}

func TestUndoUsage(t *testing.T) {
	if rc := Undo(nil); rc != 1 {
		t.Errorf("undo with no args = %d, want 1", rc)
	}
	if rc := Undo([]string{"/nonexistent/journal.json"}); rc != 1 {
		t.Errorf("undo with missing journal = %d, want 1", rc)
	}
}

func TestDoctorFixRefusesContentAddressedPath(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-ca-pkg")
	os.MkdirAll(filepath.Join(sp, "bin"), 0o755)
	f := filepath.Join(sp, "bin", "tool")
	fs := &fakeStore{
		storePaths: map[string]string{f: sp},
		ca:         map[string]bool{sp: true},
	}
	withStore(t, fs)
	blob := machofixture.Repairable(2)
	writeFixture(t, f, blob, engine.AdHoc, true)

	chdir(t, dir)
	// CA path: refused under --fix AND --fix-live; bytes untouched.
	for _, flag := range []string{"--fix", "--fix-live"} {
		if rc := Run([]string{"--quiet", flag, f}); rc != 2 {
			t.Errorf("%s rc = %d, want 2 (CA path refused)", flag, rc)
		}
		after, _ := os.ReadFile(f)
		if !engine.Check(after, f) {
			t.Fatalf("%s modified a content-addressed path", flag)
		}
	}
	if len(fs.reconcile) != 0 {
		t.Error("CA path must not be reconciled")
	}
}

func TestDoctorFixFailsClosedWhenCAQueryErrors(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-pkg")
	os.MkdirAll(filepath.Join(sp, "bin"), 0o755)
	f := filepath.Join(sp, "bin", "tool")
	fs := &fakeStore{storePaths: map[string]string{f: sp}, failCA: true}
	withStore(t, fs)
	writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 2 {
		t.Errorf("rc = %d, want 2 (unknown CA status must refuse)", rc)
	}
	after, _ := os.ReadFile(f)
	if !engine.Check(after, f) {
		t.Error("file modified although CA status was unknown")
	}
}

func TestDoctorJSONOutput(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.dylib")
	cms := filepath.Join(dir, "devid.dylib")
	writeFixture(t, broken, machofixture.Repairable(2), engine.AdHoc, true)
	writeFixture(t, cms, machofixture.CMS(2), engine.CMS, true)

	out := captureStdout(t, func() {
		if rc := Run([]string{"--json", dir}); rc != 2 {
			t.Errorf("--json with findings rc = %d, want 2", rc)
		}
	})
	var findings []struct {
		File       string `json:"file"`
		Class      string `json:"class"`
		Repairable bool   `json:"repairable"`
	}
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, out)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	// Sorted by file: broken.dylib then devid.dylib.
	if findings[0].File != broken || !findings[0].Repairable || findings[0].Class != "ad-hoc" {
		t.Errorf("finding[0] = %+v", findings[0])
	}
	if findings[1].File != cms || findings[1].Repairable || findings[1].Class != "CMS (Developer ID)" {
		t.Errorf("finding[1] = %+v", findings[1])
	}

	// Empty scan: valid JSON (empty array or null), exit 0.
	empty := t.TempDir()
	out = captureStdout(t, func() {
		if rc := Run([]string{"--json", empty}); rc != 0 {
			t.Errorf("--json empty rc = %d, want 0", rc)
		}
	})
	var none []json.RawMessage
	if err := json.Unmarshal([]byte(out), &none); err != nil {
		t.Fatalf("--json empty output invalid: %v\n%s", err, out)
	}
	if len(none) != 0 {
		t.Errorf("empty scan produced %d findings", len(none))
	}
}

func TestDoctorReportsUnverifiableAdHocAsUnrepairable(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	f := filepath.Join(dir, "mangled")
	blob := machofixture.Repairable(2)
	// Mangle the CodeDirectory's hash type to an unsupported value: the
	// signature is stale-per-Check but repair cannot fix it.
	cdOff := 2*4096 + 12 + 8
	blob[cdOff+37] = 99
	writeFixture(t, f, blob, engine.AdHoc, true)
	before := append([]byte(nil), blob...)

	out := captureStdout(t, func() {
		if rc := Run([]string{"--json", f}); rc != 2 {
			t.Errorf("rc = %d, want 2", rc)
		}
	})
	var findings []struct {
		Class      string `json:"class"`
		Repairable bool   `json:"repairable"`
	}
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Repairable {
		t.Fatalf("unverifiable ad-hoc must be unrepairable: %+v", findings)
	}
	if findings[0].Class != "ad-hoc (unverifiable)" {
		t.Errorf("class = %q", findings[0].Class)
	}
	// And --fix must not touch it (or claim success).
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 2 {
		t.Errorf("--fix rc = %d, want 2", rc)
	}
	after, _ := os.ReadFile(f)
	if string(after) != string(before) {
		t.Error("unrepairable file was modified")
	}
}

func TestWalkParallelSingleFileAndError(t *testing.T) {
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	f := filepath.Join(dir, "one")
	writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)

	var count int
	if err := walkParallel(f, scanConfig{}, func(*Finding) { count++ }); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("single-file walk found %d, want 1", count)
	}
	if err := walkParallel(filepath.Join(dir, "nonexistent"), scanConfig{}, func(*Finding) {}); err == nil {
		t.Error("nonexistent root must return an error")
	}
}

func TestScanFileEdgeCases(t *testing.T) {
	dir := t.TempDir()
	// Shorter than the magic.
	tiny := filepath.Join(dir, "tiny")
	os.WriteFile(tiny, []byte{0xfe, 0xed}, 0o644)
	if f := scanFile(tiny, scanConfig{}); f != nil {
		t.Errorf("tiny file: %+v", f)
	}
	// Magic but nothing else: Detect must say None.
	magicOnly := filepath.Join(dir, "magic-only")
	blob := make([]byte, 16)
	blob[0], blob[1], blob[2], blob[3] = 0xcf, 0xfa, 0xed, 0xfe // MH_MAGIC_64 LE
	os.WriteFile(magicOnly, blob, 0o644)
	if f := scanFile(magicOnly, scanConfig{}); f != nil {
		t.Errorf("magic-only file: %+v", f)
	}
	// Valid signed file: healthy, no finding.
	valid := machofixture.Repairable(2)
	engine.Repair(valid, "x")
	good := filepath.Join(dir, "good")
	os.WriteFile(good, valid, 0o644)
	if f := scanFile(good, scanConfig{}); f != nil {
		t.Errorf("healthy file: %+v", f)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf []byte
		tmp := make([]byte, 4096)
		for {
			n, err := r.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		done <- string(buf)
	}()
	defer func() {
		os.Stdout = old
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestDoctorFixMultiFileGroupReregistersOnce(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "abc-pkg")
	os.MkdirAll(filepath.Join(sp, "bin"), 0o755)
	a := filepath.Join(sp, "bin", "a")
	b := filepath.Join(sp, "bin", "b")
	c := filepath.Join(sp, "bin", "c")
	fs := &fakeStore{storePaths: map[string]string{a: sp, b: sp, c: sp}}
	withStore(t, fs)
	for _, f := range []string{a, b, c} {
		writeFixture(t, f, machofixture.Repairable(2), engine.AdHoc, true)
	}

	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", a, b, c}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if len(fs.reconcile) != 1 || fs.reconcile[0] != sp {
		t.Errorf("ReconcileHash calls = %v, want exactly one for %s", fs.reconcile, sp)
	}
	for _, f := range []string{a, b, c} {
		data, _ := os.ReadFile(f)
		if engine.Check(data, f) {
			t.Errorf("%s still stale", f)
		}
	}
	// All three files journaled.
	entries, _ := filepath.Glob(filepath.Join(dir, "machokeeper-undo-*.json"))
	if len(entries) != 1 {
		t.Fatalf("journals = %v", entries)
	}
	var j []journalEntry
	raw, _ := os.ReadFile(entries[0])
	json.Unmarshal(raw, &j)
	if len(j) != 3 {
		t.Errorf("journal entries = %d, want 3", len(j))
	}
}

func TestScanFileOversizedIsUnverifiableFailClosed(t *testing.T) {
	// A Mach-O-magic file above the size bound must be reported
	// unverifiable WITHOUT being loaded, and must never be repairable.
	// Uses a low env cap so no gigabyte fixture is needed.
	t.Setenv("MACHOKEEPER_MAX_FILE_SIZE", "1024")
	dir := t.TempDir()
	f := filepath.Join(dir, "huge.dylib")
	// A valid (repaired) small Mach-O would normally pass; make it
	// bigger than the cap by padding after a real signed shape so the
	// magic peek still fires.
	blob := machofixture.Repairable(2) // ~8 KiB, > 1024 cap
	if err := os.WriteFile(f, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	fnd := scanFile(f, scanConfig{})
	if fnd == nil {
		t.Fatal("oversized Mach-O must be reported, not skipped")
		return // unreachable (t.Fatal halts); silences a golangci-lint 2.12.x SA5011 false positive
	}
	if fnd.Repairable {
		t.Error("oversized file must never be repairable")
	}
	if !strings.Contains(fnd.Class, "unverifiable") {
		t.Errorf("class = %q, want an unverifiable notice", fnd.Class)
	}

	// check must fail closed (exit 2) on it.
	withStore(t, &fakeStore{})
	if rc := Check([]string{f}); rc != 2 {
		t.Errorf("check(oversized) = %d, want 2 (fail closed)", rc)
	}
	// --fix must not repair it (nothing repairable) and must not
	// corrupt it: exit 2, bytes intact.
	before, _ := os.ReadFile(f)
	chdir(t, dir)
	if rc := Run([]string{"--quiet", "--fix", f}); rc != 2 {
		t.Errorf("fix(oversized) = %d, want 2", rc)
	}
	after, _ := os.ReadFile(f)
	if string(after) != string(before) {
		t.Error("oversized file was modified")
	}
}

func TestScanFileSubCapStillVerified(t *testing.T) {
	// A file under the cap is scanned normally: a valid one is healthy,
	// a broken one is a finding. Guards against the size gate being too
	// aggressive.
	t.Setenv("MACHOKEEPER_MAX_FILE_SIZE", "1048576") // 1 MiB, well above fixtures
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken")
	os.WriteFile(broken, machofixture.Repairable(2), 0o644)
	if fnd := scanFile(broken, scanConfig{}); fnd == nil || !fnd.Repairable {
		t.Fatalf("sub-cap broken file must be a repairable finding: %+v", fnd)
	}
	valid := machofixture.Repairable(2)
	engine.Repair(valid, "x")
	good := filepath.Join(dir, "good")
	os.WriteFile(good, valid, 0o644)
	if fnd := scanFile(good, scanConfig{}); fnd != nil {
		t.Errorf("sub-cap valid file must be healthy: %+v", fnd)
	}
}

func TestReadForScanFallbackWhenTooLargeToLoad(t *testing.T) {
	// When mmap is unavailable (or fails) and the file exceeds the
	// in-memory bound, readForScan refuses rather than heap-loading.
	// We can't easily force mmap to fail, so exercise the bound logic
	// through scanFile with an in-memory cap below file size but a file
	// cap above it: the mmap path still succeeds on unix, so this
	// mainly documents the intended contract and runs clean.
	t.Setenv("MACHOKEEPER_MAX_IN_MEMORY_SIZE", "1")
	dir := t.TempDir()
	f := filepath.Join(dir, "broken")
	os.WriteFile(f, machofixture.Repairable(2), 0o644)
	// On unix mmap succeeds, so the file is still scanned (a finding).
	// The assertion is only that scanFile does not panic or misbehave.
	_ = scanFile(f, scanConfig{})
}

func TestWithGCLockAcquiresAndFallsBack(t *testing.T) {
	// Happy path: a real lock file is flocked (shared) and fn runs.
	dir := t.TempDir()
	lock := filepath.Join(dir, "gc.lock")
	os.WriteFile(lock, nil, 0o644)
	prev := gcLockPath
	gcLockPath = lock
	t.Cleanup(func() { gcLockPath = prev })

	ran := false
	if err := withGCLock(func() error { ran = true; return nil }); err != nil {
		t.Fatalf("withGCLock err: %v", err)
	}
	if !ran {
		t.Fatal("fn did not run under the lock")
	}

	// A second shared acquisition must succeed concurrently (LOCK_SH is
	// shared): hold the lock, then acquire again from another goroutine.
	unlock, err := gcLockShared(lock)
	if err != nil {
		t.Fatalf("first shared lock: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		u2, e := gcLockShared(lock)
		if e == nil {
			u2()
		}
		done <- e
	}()
	select {
	case e := <-done:
		if e != nil {
			t.Errorf("second shared lock should coexist, got: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second shared lock blocked; LOCK_SH must not exclude LOCK_SH")
	}
	unlock()

	// Best-effort: a missing lock path still runs fn (fallback).
	gcLockPath = filepath.Join(dir, "does-not-exist", "gc.lock")
	ran = false
	if err := withGCLock(func() error { ran = true; return nil }); err != nil {
		t.Fatalf("fallback err: %v", err)
	}
	if !ran {
		t.Fatal("fn must run even when the lock can't be acquired")
	}

	// Disabled ("") also runs fn.
	gcLockPath = ""
	ran = false
	_ = withGCLock(func() error { ran = true; return nil })
	if !ran {
		t.Fatal("fn must run when coordination is disabled")
	}
}

func TestScanWorkersAndFlags(t *testing.T) {
	// Explicit --jobs wins.
	cfg, rest := parseScanFlags([]string{"--jobs", "3", "/p"})
	if cfg.jobs != 3 || cfg.workers() != 3 {
		t.Errorf("--jobs 3: jobs=%d workers=%d", cfg.jobs, cfg.workers())
	}
	if len(rest) != 1 || rest[0] != "/p" {
		t.Errorf("rest = %v, want [/p]", rest)
	}

	// --jobs=N form.
	cfg, _ = parseScanFlags([]string{"--jobs=7"})
	if cfg.jobs != 7 {
		t.Errorf("--jobs=7: jobs=%d", cfg.jobs)
	}

	// Background halves the default; interactive uses all cores.
	bg := scanConfig{background: true}.workers()
	full := scanConfig{}.workers()
	if runtime.NumCPU() > 1 && bg >= full {
		t.Errorf("background workers (%d) should be < interactive (%d)", bg, full)
	}
	if bg < 1 {
		t.Errorf("background workers must be >= 1, got %d", bg)
	}

	// --background sets the flag; a bad --jobs is ignored (default).
	cfg, _ = parseScanFlags([]string{"--background", "--jobs", "notanumber"})
	if !cfg.background || cfg.jobs != 0 {
		t.Errorf("background=%v jobs=%d, want true/0", cfg.background, cfg.jobs)
	}
}

func TestBackgroundScanStillWorks(t *testing.T) {
	// A background-mode scan finds the same broken files (the tuning is
	// resource-only, not behavioral).
	withStore(t, &fakeStore{})
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "broken"), machofixture.Repairable(2), engine.AdHoc, true)
	if rc := Run([]string{"--quiet", "--background", "--jobs", "1", dir}); rc != 2 {
		t.Errorf("background scan rc = %d, want 2", rc)
	}
}

func TestJobsDoesNotSwallowPath(t *testing.T) {
	// A non-number after --jobs must NOT be consumed (else a typo like
	// `doctor --jobs /nix/store/x` silently drops the path).
	cfg, rest := parseScanFlags([]string{"--jobs", "/nix/store/x"})
	if cfg.jobs != 0 {
		t.Errorf("jobs = %d, want 0 (non-number ignored)", cfg.jobs)
	}
	if len(rest) != 1 || rest[0] != "/nix/store/x" {
		t.Errorf("rest = %v, want [/nix/store/x] (path kept, not swallowed)", rest)
	}
	// --jobs as the final arg with no value: no panic, path list intact.
	_, rest = parseScanFlags([]string{"/p", "--jobs"})
	if len(rest) != 1 || rest[0] != "/p" {
		t.Errorf("rest = %v, want [/p]", rest)
	}
}
