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
		// Length is always preserved, only journaled bytes may change,
		// and the journal reverses the repair byte-exactly.
		before := append([]byte(nil), data...)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Repair panicked: %v", r)
			}
		}()
		changed, modified, _ := Repair(data, "fuzz")
		if len(data) != len(before) {
			t.Fatalf("Repair changed length %d -> %d", len(before), len(data))
		}
		if !modified && !bytesEqual(data, before) {
			t.Fatal("Repair reported no modification but bytes changed")
		}
		// Every changed byte must be covered by a journal entry whose
		// Old matches the pre-repair bytes; un-applying the journal
		// must restore the input exactly. Un-apply in REVERSE order,
		// matching undoFile: repair wrote entries forward, so on
		// overlapping slot regions (two SuperBlob entries may point at
		// overlapping CodeDirectories) only last-undone-first restores
		// the original bytes.
		undo := append([]byte(nil), data...)
		for i := len(changed) - 1; i >= 0; i-- {
			c := changed[i]
			if c.Offset < 0 || c.Offset+int64(len(c.Old)) > int64(len(undo)) {
				t.Fatalf("journal entry out of bounds: off=%d len=%d", c.Offset, len(c.Old))
			}
			copy(undo[c.Offset:], c.Old)
		}
		if !bytesEqual(undo, before) {
			t.Fatal("journal does not reverse the repair byte-exactly")
		}
	})
}
