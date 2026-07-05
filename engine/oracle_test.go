package engine

// Cross-validation against the independent oracle: a from-scratch
// Python page-hash verifier (internal/oracle/stale.py) that shares no
// code with this engine. The engine's own Check must agree with the
// oracle on stale-slot counts before and after repair. This is the
// same dual-oracle discipline the engine's C++ ancestor was validated
// with against real cache.nixos.org binaries.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func oracleStaleCount(t *testing.T, data []byte) int {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available; oracle cross-validation skipped")
	}
	f := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, "../internal/oracle/stale.py", f).Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("oracle output %q: %v", out, err)
	}
	return n
}

func TestOracleAgreesAcrossRepair(t *testing.T) {
	cases := []struct {
		name  string
		cds   []cdSpec
		pages int
	}{
		{"sha256", []cdSpec{{csHashTypeSHA256, 32}}, 3},
		{"dual-cd", []cdSpec{{csHashTypeSHA256, 32}, {csHashTypeSHA1, 20}}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := makeRepairableSlice(tc.cds, tc.pages, 0)

			// Before: both must see stale slots.
			wantStale := 0
			for _, cd := range tc.cds {
				_ = cd
				wantStale += tc.pages
			}
			if got := oracleStaleCount(t, s); got != wantStale {
				t.Fatalf("oracle before: got %d stale, want %d", got, wantStale)
			}
			if !Check(s, "fixture") {
				t.Fatal("engine must see stale slots")
			}

			// Repair, then both must see zero.
			if _, modified, err := Repair(s, "fixture"); err != nil || !modified {
				t.Fatalf("repair: %v %v", modified, err)
			}
			if got := oracleStaleCount(t, s); got != 0 {
				t.Fatalf("oracle after: %d stale slots remain", got)
			}
			if Check(s, "fixture") {
				t.Fatal("engine must pass after repair")
			}
		})
	}
}

func TestOracleAgreesOnFat(t *testing.T) {
	slice := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0)
	fat := makeFat([][]byte{slice, slice}, false)
	if got := oracleStaleCount(t, fat); got != 4 {
		t.Fatalf("oracle fat before: %d, want 4", got)
	}
	if _, _, err := Repair(fat, "fixture"); err != nil {
		t.Fatal(err)
	}
	if got := oracleStaleCount(t, fat); got != 0 {
		t.Fatalf("oracle fat after: %d stale remain", got)
	}
}
