package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/machokeeper/machokeeper/engine"
)

// Old-format journal (no New field) must still undo — backward compat.
func TestUndoOldJournalWithoutNewField(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, []byte("AAAABBBB"), 0o644)
	j := []journalEntry{{File: f, Time: time.Now(), Changes: []engine.Change{
		{Offset: 0, Old: []byte("XXXX")}, // no New: verification skipped
	}}}
	raw, _ := json.Marshal(j)
	jp := filepath.Join(dir, "machokeeper-undo-1.json")
	os.WriteFile(jp, raw, 0o600)
	if rc := Undo([]string{jp}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	got, _ := os.ReadFile(f)
	if string(got) != "XXXXBBBB" {
		t.Errorf("got %q", got)
	}
}

// A journal naming multiple files where one fails must restore the
// others and exit non-zero.
func TestUndoPartialFailure(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("AAAA"), 0o644)
	j := []journalEntry{
		{File: filepath.Join(dir, "missing"), Changes: []engine.Change{{Offset: 0, Old: []byte("Z")}}},
		{File: good, Changes: []engine.Change{{Offset: 0, Old: []byte("Q"), New: []byte("A")}}},
	}
	raw, _ := json.Marshal(j)
	jp := filepath.Join(dir, "machokeeper-undo-2.json")
	os.WriteFile(jp, raw, 0o600)
	if rc := Undo([]string{jp}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	got, _ := os.ReadFile(good)
	if string(got) != "QAAA" {
		t.Errorf("good file not restored: %q", got)
	}
}

// A crafted journal with an offset near MaxInt64 must refuse cleanly,
// never panic (the naive Offset+len(Old) sum wraps negative).
func TestUndoRefusesOverflowingOffset(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, []byte("AAAABBBB"), 0o644)
	j := []journalEntry{{File: f, Changes: []engine.Change{
		{Offset: 9223372036854775802, Old: []byte("XXXX")},
	}}}
	raw, _ := json.Marshal(j)
	jp := filepath.Join(dir, "machokeeper-undo-3.json")
	os.WriteFile(jp, raw, 0o600)
	if rc := Undo([]string{jp}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	got, _ := os.ReadFile(f)
	if string(got) != "AAAABBBB" {
		t.Errorf("file modified: %q", got)
	}
}

// The core Change.New guard: same length, different content at an
// in-bounds offset must refuse. (The bounds check must not be the only
// thing standing between a stale journal and a modified file.)
func TestUndoRefusesInBoundsContentMismatch(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, []byte("AAAABBBB"), 0o644)
	j := []journalEntry{{File: f, Changes: []engine.Change{
		{Offset: 2, Old: []byte("xx"), New: []byte("ZZ")}, // file holds "AA"
	}}}
	raw, _ := json.Marshal(j)
	jp := filepath.Join(dir, "machokeeper-undo-4.json")
	os.WriteFile(jp, raw, 0o600)
	if rc := Undo([]string{jp}); rc != 1 {
		t.Fatalf("rc = %d, want 1 (content mismatch must refuse)", rc)
	}
	got, _ := os.ReadFile(f)
	if string(got) != "AAAABBBB" {
		t.Errorf("file modified on refusal: %q", got)
	}
}

// A journaled path that became a symlink since the repair is refused —
// undo must not follow it and clobber the target or replace the link.
func TestUndoRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("ZZZZBBBB"), 0o644)
	link := filepath.Join(dir, "repaired")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	j := []journalEntry{{File: link, Changes: []engine.Change{
		{Offset: 0, Old: []byte("AAAA"), New: []byte("ZZZZ")},
	}}}
	raw, _ := json.Marshal(j)
	jp := filepath.Join(dir, "machokeeper-undo-5.json")
	os.WriteFile(jp, raw, 0o600)
	if rc := Undo([]string{jp}); rc != 1 {
		t.Fatalf("rc = %d, want 1 (symlink must refuse)", rc)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "ZZZZBBBB" {
		t.Errorf("symlink target modified: %q", got)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink was replaced")
	}
}

// Undo is deliberately not idempotent: after a successful undo the
// slots hold Old, not New, so a second run refuses rather than
// re-splicing. Pin that behavior.
func TestUndoTwiceRefusesSecondRun(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, []byte("NNNNBBBB"), 0o644)
	j := []journalEntry{{File: f, Changes: []engine.Change{
		{Offset: 0, Old: []byte("OOOO"), New: []byte("NNNN")},
	}}}
	raw, _ := json.Marshal(j)
	jp := filepath.Join(dir, "machokeeper-undo-6.json")
	os.WriteFile(jp, raw, 0o600)
	if rc := Undo([]string{jp}); rc != 0 {
		t.Fatalf("first undo rc = %d", rc)
	}
	if rc := Undo([]string{jp}); rc != 1 {
		t.Fatalf("second undo rc = %d, want 1 (already undone)", rc)
	}
	got, _ := os.ReadFile(f)
	if string(got) != "OOOOBBBB" {
		t.Errorf("second run modified the file: %q", got)
	}
}
