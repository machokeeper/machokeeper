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

func TestRegistrationLines(t *testing.T) {
	got := registrationLines(
		"/nix/store/abc-pkg",
		"/nix/store/def-pkg.drv",
		"sha256:0131d5923zw1s2b5ij77ppks68hwjjlfgsc3mgd0j2dxw1lhd9n8",
		12345,
		[]string{"/nix/store/ref1", "/nix/store/ref2"},
	)
	want := "/nix/store/abc-pkg\n" +
		"/nix/store/def-pkg.drv\n" +
		"sha256:0131d5923zw1s2b5ij77ppks68hwjjlfgsc3mgd0j2dxw1lhd9n8\n" +
		"12345\n" +
		"2\n" +
		"/nix/store/ref1\n" +
		"/nix/store/ref2\n"
	if got != want {
		t.Errorf("registrationLines:\ngot  %q\nwant %q", got, want)
	}
	// No deriver, no references: empty deriver line, zero count, no
	// reference lines.
	got = registrationLines("/nix/store/abc-pkg", "", "sha256:x", 0, nil)
	want = "/nix/store/abc-pkg\n\nsha256:x\n0\n0\n"
	if got != want {
		t.Errorf("registrationLines(empty):\ngot  %q\nwant %q", got, want)
	}
}

func TestIsContentAddressedParsesBothJSONForms(t *testing.T) {
	// The exec path needs a live nix; the parsing is what can silently
	// break across nix versions, so pin both response forms here.
	cases := []struct {
		name, out string
		want      bool
	}{
		{"array-ca", `[{"path":"/nix/store/abc-pkg","ca":"fixed:r:sha256:1abc"}]`, true},
		{"array-input", `[{"path":"/nix/store/abc-pkg"}]`, false},
		{"object-ca", `{"/nix/store/abc-pkg":{"ca":"text:sha256:1abc"}}`, true},
		{"object-input", `{"/nix/store/abc-pkg":{"ca":null}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parsePathInfoCA([]byte(c.out), "/nix/store/abc-pkg")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("ca = %v, want %v", got, c.want)
			}
		})
	}
	if _, err := parsePathInfoCA([]byte(`[]`), "/nix/store/abc-pkg"); err == nil {
		t.Error("missing path must be an error (fail closed)")
	}
	if _, err := parsePathInfoCA([]byte(`not json`), "/nix/store/abc-pkg"); err == nil {
		t.Error("malformed JSON must be an error (fail closed)")
	}
}
