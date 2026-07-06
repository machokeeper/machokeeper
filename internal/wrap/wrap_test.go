package wrap

import (
	"reflect"
	"testing"
)

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"/nix/store/abc-fish-4.2.1/bin/fish":  "/nix/store/abc-fish-4.2.1",
		"/nix/store/abc-fish-4.2.1":           "/nix/store/abc-fish-4.2.1",
		"/nix/store/abc-fish-4.2.1.narinfo":   "/nix/store/abc-fish-4.2.1",
		"/nix/store/abc-fish/lib/x/y/z.dylib": "/nix/store/abc-fish",
	}
	for in, want := range cases {
		if got := cleanPath(in); got != want {
			t.Errorf("cleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dedupe = %v, want %v", got, want)
	}
}

func TestParseSubstituteEvents(t *testing.T) {
	// A representative slice of nix --log-format internal-json output:
	// a substitution line names the path in a "copying path" message,
	// and unrelated lines must be ignored.
	log := `@nix {"action":"start","text":"evaluating"}
@nix {"action":"start","fields":["/nix/store/aaa111-fish-4.2.1","https://cache.nixos.org"],"text":"copying path '/nix/store/aaa111-fish-4.2.1' from 'https://cache.nixos.org'"}
@nix {"action":"start","text":"building '/nix/store/bbb222-hello.drv'"}
@nix {"action":"start","text":"substituting '/nix/store/ccc333-zlib/lib/libz.dylib'"}
`
	got := parseSubstitutePaths(log)
	want := map[string]bool{
		"/nix/store/aaa111-fish-4.2.1": true,
		"/nix/store/ccc333-zlib":       true,
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want keys %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path parsed: %q (a .drv build path must not be treated as a substitution)", p)
		}
	}
}
