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

// Event shapes below are captured verbatim from `nix build --log-format
// internal-json --dry-run` (nix 2.3x); only ids are shortened.
func TestParseSubstitutePathsDryRunMsgs(t *testing.T) {
	log := `@nix {"action":"msg","level":0,"msg":"this path will be fetched (30.3 KiB download, 110.4 KiB unpacked):"}
@nix {"action":"msg","level":0,"msg":"  /nix/store/aaa111-hello-2.12.3"}
@nix {"action":"msg","level":0,"msg":"  /nix/store/bbb222-fish-4.2.1"}
@nix {"action":"msg","level":0,"msg":"building '/nix/store/ccc333-x.drv'..."}
@nix {"action":"msg","level":0,"msg":"  /nix/store/ddd444-should-not-count"}
`
	got := parseSubstitutePaths(log)
	want := []string{"/nix/store/aaa111-hello-2.12.3", "/nix/store/bbb222-fish-4.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed %v, want %v (the fetch list ends at the first non-path message)", got, want)
	}
}

func TestParseSubstitutePathsActivities(t *testing.T) {
	log := `@nix {"action":"start","fields":["/nix/store/aaa111-fish-4.2.1","https://cache.nixos.org"],"id":1,"level":4,"parent":0,"text":"querying info about '/nix/store/aaa111-fish-4.2.1'","type":109}
@nix {"action":"start","fields":["https://cache.nixos.org/aaa111.narinfo"],"id":2,"level":4,"parent":1,"text":"downloading","type":101}
@nix {"action":"start","fields":["/nix/store/bbb222-zlib","https://cache.nixos.org"],"id":3,"level":4,"parent":0,"text":"copying path '/nix/store/bbb222-zlib'","type":100}
@nix {"action":"start","id":4,"level":6,"parent":0,"text":"building '/nix/store/ccc333-x.drv'","type":105}
@nix {"action":"result","fields":[0,0],"id":2,"type":105}
not-a-nix-line /nix/store/eee555-ignored
`
	got := parseSubstitutePaths(log)
	want := []string{"/nix/store/aaa111-fish-4.2.1", "/nix/store/bbb222-zlib"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed %v, want %v (only type 100/109 activities carry substitution paths)", got, want)
	}
}

func TestParseSubstitutePathsIgnoresMalformedJSON(t *testing.T) {
	log := "@nix {truncated\n@nix []\n@nix {\"action\":\"start\",\"type\":100,\"fields\":[42]}\n"
	if got := parseSubstitutePaths(log); len(got) != 0 {
		t.Errorf("malformed input parsed to %v, want empty", got)
	}
}
