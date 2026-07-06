package hook

import (
	"os"
	"reflect"
	"sort"
	"testing"
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
