package nixstore

import (
	"path/filepath"
	"testing"
)

func TestStorePathOf(t *testing.T) {
	store := t.TempDir()
	t.Setenv("NIX_STORE_DIR", store)

	sp := filepath.Join(store, "abc123-fish-4.2.1")
	cases := []struct {
		in       string
		wantPath string
		wantOK   bool
	}{
		{filepath.Join(sp, "bin", "fish"), sp, true},
		{sp, sp, true},
		{filepath.Join(store, "abc123-fish-4.2.1", "lib", "x", "y"), sp, true},
		{"/etc/passwd", "", false},
		{filepath.Join(t.TempDir(), "loose"), "", false},
	}
	for _, c := range cases {
		got, ok := StorePathOf(c.in)
		if ok != c.wantOK || got != c.wantPath {
			t.Errorf("StorePathOf(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.wantPath, c.wantOK)
		}
	}
}
