package engine

import "testing"

// Native Go fuzz targets (`go test -fuzz`). The engine parses bytes
// from untrusted builders and substituters, so the invariant is that
// neither detection nor check/repair ever panics or reads out of
// bounds on any input — the memory-safety property the C++ ancestor
// relied on ASan/UBSan for. CI runs these for a bounded time; a
// developer can run them open-endedly with `-fuzz`.

func seedCorpus(f *testing.F) {
	base := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 4, 16)
	dual := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}, {csHashTypeSHA1, 20}}, 2, 0)
	for _, s := range [][]byte{
		base,
		dual,
		makeFat([][]byte{base, makeUnsignedSlice64()}, false),
		makeFat([][]byte{base}, true),
		makeSignedSlice64(100),
		makeSignedSlice64(0),
		makeUnsignedSlice64(),
		make([]byte, 40),
		{},
	} {
		f.Add(s)
	}
}

func FuzzDetect(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Detect(data) // must not panic or read OOB
	})
}

func FuzzCheck(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		before := append([]byte(nil), data...)
		_ = Check(data, "fuzz")
		// Check is read-only.
		if !bytesEqual(before, data) {
			t.Fatal("Check mutated its input")
		}
	})
}

func FuzzRepair(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		// Repair may return an error (e.g. CMS) but must never panic.
		// Length is always preserved.
		n := len(data)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Repair panicked: %v", r)
			}
		}()
		_, _, _ = Repair(data, "fuzz")
		if len(data) != n {
			t.Fatalf("Repair changed length %d -> %d", n, len(data))
		}
	})
}
