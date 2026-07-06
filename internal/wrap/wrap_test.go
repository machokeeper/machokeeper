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

// withSeams swaps all four orchestration seams and restores them.
func withSeams(t *testing.T, subs func([]string) []string, real func([]string) []string, pass func([]string) int, fix func([]string) int) {
	t.Helper()
	pSubs, pReal, pPass, pFix := willSubstituteFn, realiseFn, passthroughFn, fixFn
	willSubstituteFn, realiseFn, passthroughFn, fixFn = subs, real, pass, fix
	t.Cleanup(func() {
		willSubstituteFn, realiseFn, passthroughFn, fixFn = pSubs, pReal, pPass, pFix
	})
}

func TestRunPrefetchesRepairsAndSucceeds(t *testing.T) {
	var fixed [][]string
	var runs int
	withSeams(t,
		func([]string) []string { return []string{"/nix/store/aaa-x"} },
		func(p []string) []string { return p },
		func([]string) int { runs++; return 0 },
		func(p []string) int { fixed = append(fixed, p); return 0 },
	)
	if rc := Run([]string{"nix", "build"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if runs != 1 {
		t.Errorf("command ran %d times, want 1", runs)
	}
	if len(fixed) != 1 || fixed[0][0] != "/nix/store/aaa-x" {
		t.Errorf("fix calls = %v", fixed)
	}
}

func TestRunRetriesOnceAfterRepair(t *testing.T) {
	runs := 0
	withSeams(t,
		func([]string) []string { return []string{"/nix/store/aaa-x"} },
		func(p []string) []string { return p },
		func([]string) int {
			runs++
			if runs == 1 {
				return 1 // first run fails
			}
			return 0 // retry succeeds
		},
		func([]string) int { return 0 },
	)
	if rc := Run([]string{"nix", "build"}); rc != 0 {
		t.Fatalf("rc = %d, want 0 after retry", rc)
	}
	if runs != 2 {
		t.Errorf("command ran %d times, want 2 (fail + one retry)", runs)
	}
}

func TestRunNoRetryWhenNothingToRepair(t *testing.T) {
	runs := 0
	withSeams(t,
		func([]string) []string { return nil }, // nothing substituted
		func(p []string) []string { return p },
		func([]string) int { runs++; return 3 },
		func([]string) int { t.Error("fix must not be called"); return 0 },
	)
	if rc := Run([]string{"nix", "build"}); rc != 3 {
		t.Fatalf("rc = %d, want the command's own exit code 3", rc)
	}
	if runs != 1 {
		t.Errorf("command ran %d times, want 1 (no retry without a repair)", runs)
	}
}

func TestRunRetryFailurePropagatesRetryExitCode(t *testing.T) {
	runs := 0
	withSeams(t,
		func([]string) []string { return []string{"/nix/store/aaa-x"} },
		func(p []string) []string { return p },
		func([]string) int { runs++; return 7 }, // fails both times
		func([]string) int { return 0 },
	)
	if rc := Run([]string{"nix", "build"}); rc != 7 {
		t.Fatalf("rc = %d, want 7", rc)
	}
	if runs != 2 {
		t.Errorf("runs = %d, want 2 (exactly one retry, never more)", runs)
	}
}

func TestRunNoArgs(t *testing.T) {
	if rc := Run(nil); rc != 1 {
		t.Errorf("rc = %d, want 1", rc)
	}
}
