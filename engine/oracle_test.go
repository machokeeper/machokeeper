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
		// CI sets MACHOKEEPER_REQUIRE_ORACLE=1 so the triad's third leg
		// can never silently vanish with a green build; locally the
		// skip stays visible via -v.
		if os.Getenv("MACHOKEEPER_REQUIRE_ORACLE") != "" {
			t.Fatal("python3 not available but MACHOKEEPER_REQUIRE_ORACLE is set; the oracle leg must run")
		}
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

func TestOracleAgreesOnCodeLimitClamp(t *testing.T) {
	// The one adversarial shape BOTH sides define behavior for: a
	// codeLimit that truncates the final page. Engine and oracle each
	// clamp to codeLimit; they must agree before and after repair.
	s := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0)
	cdOff := 2*4096 + 12 + 8
	putBE32(s, cdOff+32, uint32(2*4096-100))

	if got := oracleStaleCount(t, s); got != 2 {
		t.Fatalf("oracle before: %d, want 2", got)
	}
	if !Check(s, "fixture") {
		t.Fatal("engine must agree: stale")
	}
	if _, modified, err := Repair(s, "fixture"); err != nil || !modified {
		t.Fatalf("repair: %v %v", modified, err)
	}
	if got := oracleStaleCount(t, s); got != 0 {
		t.Fatalf("oracle after: %d stale remain — engine and oracle disagree on clamping", got)
	}
	if Check(s, "fixture") {
		t.Fatal("engine must pass after clamped repair")
	}
}

func TestOracleAgreesOnSpecialSlots(t *testing.T) {
	// Special slots offset the code-slot region via hashOffset; both
	// sides must locate the code slots identically.
	s := makeSpecialSlotSlice(3, 2)
	if got := oracleStaleCount(t, s); got != 2 {
		t.Fatalf("oracle before: %d, want 2", got)
	}
	if _, modified, err := Repair(s, "fixture"); err != nil || !modified {
		t.Fatalf("repair: %v %v", modified, err)
	}
	if got := oracleStaleCount(t, s); got != 0 {
		t.Fatalf("oracle after: %d stale — hashOffset handling diverges", got)
	}
}
