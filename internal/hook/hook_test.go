package hook

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/machokeeper/machokeeper/engine"
	"github.com/machokeeper/machokeeper/internal/machofixture"
)

func TestClosureDeltaSubtractsOldGeneration(t *testing.T) {
	// Inject a fake `nix-store --query --requisites` so the delta logic
	// is tested without a store.
	prev := requisitesFn
	defer func() { requisitesFn = prev }()
	requisitesFn = func(path string) ([]string, error) {
		switch path {
		case "new":
			return []string{"/nix/store/a", "/nix/store/b", "/nix/store/c"}, nil
		case "old":
			return []string{"/nix/store/a", "/nix/store/b"}, nil
		}
		return nil, nil
	}

	delta, err := closureDelta("new", "old")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(delta, []string{"/nix/store/c"}) {
		t.Errorf("delta = %v, want [/nix/store/c]", delta)
	}
}

func TestClosureDeltaNoOldReturnsWholeClosure(t *testing.T) {
	prev := requisitesFn
	defer func() { requisitesFn = prev }()
	requisitesFn = func(path string) ([]string, error) {
		return []string{"/nix/store/a", "/nix/store/b"}, nil
	}
	delta, err := closureDelta("new", "")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(delta)
	if !reflect.DeepEqual(delta, []string{"/nix/store/a", "/nix/store/b"}) {
		t.Errorf("delta = %v", delta)
	}
}

func TestPostBuildIsFailOpenWithNoOutPaths(t *testing.T) {
	os.Unsetenv("OUT_PATHS")
	if rc := PostBuild(); rc != 0 {
		t.Errorf("PostBuild with no OUT_PATHS = %d, want 0", rc)
	}
}

func TestScanGenerationFailsOpenOnDeltaError(t *testing.T) {
	prev := requisitesFn
	defer func() { requisitesFn = prev }()
	requisitesFn = func(path string) ([]string, error) {
		return nil, os.ErrNotExist // e.g. a bogus generation path
	}
	// Even when the closure can't be computed, activation must not be
	// blocked in repair mode.
	if rc := ScanGeneration("bad", "", "repair"); rc != 0 {
		t.Errorf("ScanGeneration fail-open = %d, want 0", rc)
	}
}

func TestScanGenerationRefuseModeBlocksOnBroken(t *testing.T) {
	prev := requisitesFn
	defer func() { requisitesFn = prev }()

	dir := t.TempDir()
	broken := filepath.Join(dir, "abc-pkg")
	os.MkdirAll(broken, 0o755)
	blob := machofixture.Repairable(2)
	if err := os.WriteFile(filepath.Join(broken, "tool"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	requisitesFn = func(path string) ([]string, error) {
		return []string{broken}, nil
	}
	// Refuse mode: broken signature in the delta must block (exit 1).
	if rc := ScanGeneration("new", "", "refuse"); rc != 1 {
		t.Errorf("refuse mode with broken delta = %d, want 1", rc)
	}
	// The file must NOT have been repaired by a refuse-mode scan.
	after, _ := os.ReadFile(filepath.Join(broken, "tool"))
	if string(after) != string(blob) {
		t.Error("refuse mode modified a file")
	}
}

func TestScanGenerationRefuseModePassesWhenClean(t *testing.T) {
	prev := requisitesFn
	defer func() { requisitesFn = prev }()

	dir := t.TempDir()
	clean := filepath.Join(dir, "abc-pkg")
	os.MkdirAll(clean, 0o755)
	valid := machofixture.Repairable(2)
	engine.Repair(valid, "x")
	if err := os.WriteFile(filepath.Join(clean, "tool"), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	requisitesFn = func(path string) ([]string, error) {
		return []string{clean}, nil
	}
	if rc := ScanGeneration("new", "", "refuse"); rc != 0 {
		t.Errorf("refuse mode with clean delta = %d, want 0", rc)
	}
}

func TestScanGenerationRefuseModeEmptyDelta(t *testing.T) {
	prev := requisitesFn
	defer func() { requisitesFn = prev }()
	requisitesFn = func(path string) ([]string, error) {
		return []string{"/nix/store/a"}, nil // same for new and old
	}
	if rc := ScanGeneration("new", "old", "refuse"); rc != 0 {
		t.Errorf("empty delta = %d, want 0", rc)
	}
}
