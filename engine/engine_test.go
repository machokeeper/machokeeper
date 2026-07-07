package engine

// The detector and engine are content-based, so these tests run on
// every platform. Byte fixtures are built by hand from the on-disk
// layouts in <mach-o/loader.h>, <mach-o/fat.h> and xnu's codesign.h.
// Ported from the C++ suite validated on the NixOS/nix#15638 branch.

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func putLE32(s []byte, off int, v uint32) { binary.LittleEndian.PutUint32(s[off:], v) }
func putBE32(s []byte, off int, v uint32) { binary.BigEndian.PutUint32(s[off:], v) }
func putBE64(s []byte, off int, v uint64) { binary.BigEndian.PutUint64(s[off:], v) }

// makeSignedSlice64 builds a minimal signed 64-bit slice:
// mach_header_64, one LC_CODE_SIGNATURE, and a SuperBlob containing a
// CodeDirectory header plus optionally a CMS blob wrapper of cmsLen
// payload bytes (0 = no signature slot, 8 = the empty ad-hoc wrapper,
// >8 = Developer-ID-style).
func makeSignedSlice64(cmsLen int) []byte {
	const headerSize = 32
	const lcSize = 16
	haveCms := cmsLen > 0
	nBlobs := 1
	if haveCms {
		nBlobs = 2
	}
	sbHeader := 12 + nBlobs*8
	cdLen := 44
	sigSize := sbHeader + cdLen
	if haveCms {
		sigSize += cmsLen
	}
	sigOff := headerSize + lcSize
	s := make([]byte, sigOff+sigSize)

	putLE32(s, 0, machMagic64)
	putLE32(s, 16, 1)      // ncmds
	putLE32(s, 20, lcSize) // sizeofcmds

	putLE32(s, headerSize+0, lcCodeSignature)
	putLE32(s, headerSize+4, lcSize)
	putLE32(s, headerSize+8, uint32(sigOff))
	putLE32(s, headerSize+12, uint32(sigSize))

	putBE32(s, sigOff+0, csMagicEmbeddedSignature)
	putBE32(s, sigOff+4, uint32(sigSize))
	putBE32(s, sigOff+8, uint32(nBlobs))
	putBE32(s, sigOff+12, 0) // CSSLOT_CODEDIRECTORY
	putBE32(s, sigOff+16, uint32(sbHeader))
	if haveCms {
		putBE32(s, sigOff+20, csSlotSignature)
		putBE32(s, sigOff+24, uint32(sbHeader+cdLen))
	}
	cdOff := sigOff + sbHeader
	putBE32(s, cdOff+0, csMagicCodeDirectory)
	putBE32(s, cdOff+4, uint32(cdLen))
	if haveCms {
		cmsOff := cdOff + cdLen
		putBE32(s, cmsOff+0, csMagicBlobWrapper)
		putBE32(s, cmsOff+4, uint32(cmsLen))
	}
	return s
}

// makeUnsignedSlice64: one non-signature load command.
func makeUnsignedSlice64() []byte {
	const headerSize = 32
	const lcSize = 16
	s := make([]byte, headerSize+lcSize)
	putLE32(s, 0, machMagic64)
	putLE32(s, 16, 1)
	putLE32(s, 20, lcSize)
	putLE32(s, headerSize+0, 0x32) // LC_SOURCE_VERSION
	putLE32(s, headerSize+4, lcSize)
	return s
}

// makeFat wraps slices into a fat container (32- or 64-bit headers).
func makeFat(slices [][]byte, fat64 bool) []byte {
	archSize := fatArchSize32
	magic := uint32(fatMagic32)
	if fat64 {
		archSize = fatArchSize64
		magic = fatMagic64
	}
	tableEnd := 8 + len(slices)*archSize
	cur := (tableEnd + 15) &^ 15
	offsets := make([]int, len(slices))
	for i, sl := range slices {
		offsets[i] = cur
		cur += (len(sl) + 15) &^ 15
	}
	s := make([]byte, cur)
	putBE32(s, 0, magic)
	putBE32(s, 4, uint32(len(slices)))
	for i, sl := range slices {
		archOff := 8 + i*archSize
		if fat64 {
			putBE64(s, archOff+8, uint64(offsets[i]))
			putBE64(s, archOff+16, uint64(len(sl)))
		} else {
			putBE32(s, archOff+8, uint32(offsets[i]))
			putBE32(s, archOff+12, uint32(len(sl)))
		}
		copy(s[offsets[i]:], sl)
	}
	return s
}

type cdSpec struct {
	hashType, hashSize int
}

// makeRepairableSlice builds a signed slice whose CodeDirectories
// carry real page-hash slots, initialized to ZERO (stale), so a
// repair must rewrite every one. Page size 4096; codeLimit = sigOff.
func makeRepairableSlice(cds []cdSpec, pages int, cmsLen int) []byte {
	const headerSize = 32
	const lcSize = 16
	const pageSize = 4096

	sigOff := pages * pageSize
	nCodeSlots := pages
	haveCms := cmsLen > 0
	nBlobs := len(cds)
	if haveCms {
		nBlobs++
	}
	sbHeader := 12 + nBlobs*8
	cdLens := make([]int, len(cds))
	cdsTotal := 0
	for i, cd := range cds {
		cdLens[i] = 44 + nCodeSlots*cd.hashSize
		cdsTotal += cdLens[i]
	}
	sigSize := sbHeader + cdsTotal
	if haveCms {
		sigSize += cmsLen
	}
	s := bytes.Repeat([]byte{'A'}, sigOff+sigSize)

	putLE32(s, 0, machMagic64)
	putLE32(s, 16, 1)
	putLE32(s, 20, lcSize)
	putLE32(s, headerSize+0, lcCodeSignature)
	putLE32(s, headerSize+4, lcSize)
	putLE32(s, headerSize+8, uint32(sigOff))
	putLE32(s, headerSize+12, uint32(sigSize))

	putBE32(s, sigOff+0, csMagicEmbeddedSignature)
	putBE32(s, sigOff+4, uint32(sigSize))
	putBE32(s, sigOff+8, uint32(nBlobs))
	cursor := sbHeader
	for i := range cds {
		slot := uint32(0)
		if i > 0 {
			slot = uint32(0x1000 + i) // alternate CD slots
		}
		putBE32(s, sigOff+12+i*8, slot)
		putBE32(s, sigOff+16+i*8, uint32(cursor))
		cursor += cdLens[i]
	}
	if haveCms {
		putBE32(s, sigOff+12+len(cds)*8, csSlotSignature)
		putBE32(s, sigOff+16+len(cds)*8, uint32(cursor))
	}
	cursor = sbHeader
	for i, cd := range cds {
		cdOff := sigOff + cursor
		putBE32(s, cdOff+0, csMagicCodeDirectory)
		putBE32(s, cdOff+4, uint32(cdLens[i]))
		putBE32(s, cdOff+16, 44)                 // hashOffset
		putBE32(s, cdOff+24, 0)                  // nSpecialSlots
		putBE32(s, cdOff+28, uint32(nCodeSlots)) // nCodeSlots
		putBE32(s, cdOff+32, uint32(sigOff))     // codeLimit
		s[cdOff+36] = byte(cd.hashSize)
		s[cdOff+37] = byte(cd.hashType)
		s[cdOff+39] = 12 // pageSizeLog2
		for j := 0; j < nCodeSlots*cd.hashSize; j++ {
			s[cdOff+44+j] = 0
		}
		cursor += cdLens[i]
	}
	if haveCms {
		cmsOff := sigOff + cursor
		putBE32(s, cmsOff+0, csMagicBlobWrapper)
		putBE32(s, cmsOff+4, uint32(cmsLen))
	}
	return s
}

// expectAllSlotsValid verifies every hash slot of every CD against a
// recompute.
func expectAllSlotsValid(t *testing.T, s []byte, cds []cdSpec, pages int) {
	t.Helper()
	const pageSize = 4096
	sigOff := pages * pageSize
	nBlobs := int(binary.BigEndian.Uint32(s[sigOff+8:]))
	sbHeader := 12 + nBlobs*8
	cursor := sbHeader
	for _, cd := range cds {
		cdOff := sigOff + cursor
		for i := 0; i < pages; i++ {
			page := s[i*pageSize : (i+1)*pageSize]
			var sum []byte
			if cd.hashType == csHashTypeSHA256 {
				h := sha256.Sum256(page)
				sum = h[:]
			} else {
				h := sha1.Sum(page)
				sum = h[:]
			}
			slot := s[cdOff+44+i*cd.hashSize : cdOff+44+(i+1)*cd.hashSize]
			if !bytes.Equal(slot, sum) {
				t.Errorf("stale slot: cd hashType=%d page %d", cd.hashType, i)
			}
		}
		cursor += 44 + pages*cd.hashSize
	}
}

/* ---------------- Detect ---------------- */

func TestDetectEmptyAndTiny(t *testing.T) {
	if Detect(nil) != None || Detect(make([]byte, 27)) != None {
		t.Fatal("tiny inputs must be None")
	}
}

func TestDetectUnsignedThin(t *testing.T) {
	if Detect(makeUnsignedSlice64()) != None {
		t.Fatal("unsigned slice must be None")
	}
}

func TestDetectAdHocThin(t *testing.T) {
	if Detect(makeSignedSlice64(0)) != AdHoc {
		t.Fatal("want AdHoc")
	}
	if Detect(makeSignedSlice64(8)) != AdHoc {
		t.Fatal("empty CMS wrapper is still AdHoc")
	}
}

func TestDetectCMSThin(t *testing.T) {
	if Detect(makeSignedSlice64(100)) != CMS {
		t.Fatal("want CMS")
	}
}

func TestDetectFatContainers(t *testing.T) {
	signed := makeSignedSlice64(0)
	unsigned := makeUnsignedSlice64()
	if Detect(makeFat([][]byte{unsigned, signed}, false)) != AdHoc {
		t.Fatal("fat32 strongest-kind")
	}
	if Detect(makeFat([][]byte{signed}, true)) != AdHoc {
		t.Fatal("fat64")
	}
	if Detect(makeFat([][]byte{makeSignedSlice64(100), signed}, false)) != CMS {
		t.Fatal("strongest kind wins")
	}
}

func TestDetectJavaClassFile(t *testing.T) {
	// Java .class files share the fat32 magic; their version field
	// reads as nfat_arch and their "slices" carry no Mach-O magic.
	s := make([]byte, 64)
	putBE32(s, 0, 0xcafebabe)
	putBE32(s, 4, 65) // minor=0, major=65 → nfat=65 within cap? 65 < 128
	if Detect(s) != None {
		t.Fatal("class file must be None")
	}
}

func TestDetectAbsurdNFatArch(t *testing.T) {
	s := make([]byte, 64)
	putBE32(s, 0, fatMagic32)
	putBE32(s, 4, 1<<20)
	if Detect(s) != None {
		t.Fatal("absurd nfat must be None")
	}
}

func TestDetectFatZeroArchesAndBadOffsets(t *testing.T) {
	s := make([]byte, 64)
	putBE32(s, 0, fatMagic32)
	putBE32(s, 4, 0)
	if Detect(s) != None {
		t.Fatal("nfat=0")
	}
	s2 := make([]byte, 8+20)
	putBE32(s2, 0, fatMagic32)
	putBE32(s2, 4, 1)
	putBE32(s2, 8+8, 0x7fffffff) // offset beyond EOF
	putBE32(s2, 8+12, 64)
	if Detect(s2) != None {
		t.Fatal("slice offset beyond EOF")
	}
}

func TestDetectFat64HugeOffsetNoOverflow(t *testing.T) {
	s := make([]byte, 8+32)
	putBE32(s, 0, fatMagic64)
	putBE32(s, 4, 1)
	putBE64(s, 8+8, ^uint64(0)-8)
	putBE64(s, 8+16, 1024)
	if Detect(s) != None {
		t.Fatal("u64 offset must not wrap into bounds")
	}
}

func TestDetectTruncatedAndZeroSizeLoadCommands(t *testing.T) {
	s := makeSignedSlice64(0)
	putLE32(s, 20, 0xffff) // sizeofcmds beyond EOF
	if Detect(s) != None {
		t.Fatal("truncated load commands")
	}
	s2 := makeSignedSlice64(0)
	putLE32(s2, 32+4, 0) // cmdsize = 0
	if Detect(s2) != None {
		t.Fatal("zero-size load command")
	}
}

func TestDetectFatSliceBoundsMatchEngine(t *testing.T) {
	// A zero-size arch entry is invalid to both the detector and the
	// repair walker: a slice one walks and the other skips could pass
	// a check it was never given.
	slice := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0)
	fat := makeFat([][]byte{slice}, false)
	putBE32(fat, 8+12, 0) // fat_arch.size = 0
	if Detect(fat) != None {
		t.Fatal("zero-size slice must be None")
	}
	if Check(fat, "test") {
		t.Fatal("check must agree with detect")
	}
}

/* ---------------- Repair engine ---------------- */

func TestRepairStaleSHA256Slots(t *testing.T) {
	cds := []cdSpec{{csHashTypeSHA256, 32}}
	s := makeRepairableSlice(cds, 3, 0)
	_, modified, err := Repair(s, "test")
	if err != nil || !modified {
		t.Fatalf("repair: modified=%v err=%v", modified, err)
	}
	expectAllSlotsValid(t, s, cds, 3)
	// Idempotent: a second run finds nothing stale.
	_, modified, _ = Repair(s, "test")
	if modified {
		t.Fatal("second repair must be a no-op")
	}
}

func TestRepairDualSHA1SHA256(t *testing.T) {
	cds := []cdSpec{{csHashTypeSHA256, 32}, {csHashTypeSHA1, 20}}
	s := makeRepairableSlice(cds, 2, 0)
	if _, modified, err := Repair(s, "test"); err != nil || !modified {
		t.Fatalf("repair: %v %v", modified, err)
	}
	expectAllSlotsValid(t, s, cds, 2)
	if Check(s, "test") {
		t.Fatal("check must pass after dual-CD repair")
	}
}

func TestCheckReportsWithoutModifying(t *testing.T) {
	s := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0)
	before := append([]byte(nil), s...)
	if !Check(s, "test") {
		t.Fatal("stale slice must fail check")
	}
	if !bytes.Equal(s, before) {
		t.Fatal("check must never mutate")
	}
}

func TestRepairPreservesNonSlotBytes(t *testing.T) {
	cds := []cdSpec{{csHashTypeSHA256, 32}}
	s := makeRepairableSlice(cds, 2, 0)
	before := append([]byte(nil), s...)
	changed, modified, err := Repair(s, "test")
	if err != nil || !modified {
		t.Fatal("repair failed")
	}
	// Only the recorded slots may differ, and undo restores exactly.
	for _, c := range changed {
		copy(s[c.Offset:], c.Old)
	}
	if !bytes.Equal(s, before) {
		t.Fatal("undo journal must restore byte-exact")
	}
}

func TestRepairRefusesCMS(t *testing.T) {
	s := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 100)
	before := append([]byte(nil), s...)
	_, _, err := Repair(s, "test")
	if err == nil {
		t.Fatal("CMS repair must be refused")
	}
	if !bytes.Equal(s, before) {
		t.Fatal("refusal must not touch bytes")
	}
	// ...but check mode verifies it like any other slice.
	if !Check(s, "test") {
		t.Fatal("stale CMS slice must fail check")
	}
}

func TestEmptyCMSWrapperIsRepairable(t *testing.T) {
	cds := []cdSpec{{csHashTypeSHA256, 32}}
	s := makeRepairableSlice(cds, 2, 8)
	if _, modified, err := Repair(s, "test"); err != nil || !modified {
		t.Fatalf("empty wrapper must repair: %v %v", modified, err)
	}
	expectAllSlotsValid(t, s, cds, 2)
}

func TestLastPageClampedToCodeLimit(t *testing.T) {
	cds := []cdSpec{{csHashTypeSHA256, 32}}
	s := makeRepairableSlice(cds, 2, 0)
	const pageSize = 4096
	sigOff := 2 * pageSize
	cdOff := sigOff + 12 + 8
	truncated := uint32(sigOff - 100)
	putBE32(s, cdOff+32, truncated)
	if _, modified, err := Repair(s, "test"); err != nil || !modified {
		t.Fatal("repair failed")
	}
	h0 := sha256.Sum256(s[0:pageSize])
	if !bytes.Equal(s[cdOff+44:cdOff+44+32], h0[:]) {
		t.Fatal("page 0 slot")
	}
	h1 := sha256.Sum256(s[pageSize:truncated])
	if !bytes.Equal(s[cdOff+44+32:cdOff+44+64], h1[:]) {
		t.Fatal("clamped last page slot")
	}
}

func TestRepairFatContainers(t *testing.T) {
	cds := []cdSpec{{csHashTypeSHA256, 32}}
	slice := makeRepairableSlice(cds, 2, 0)
	fat := makeFat([][]byte{slice, slice}, false)
	if _, modified, err := Repair(fat, "test"); err != nil || !modified {
		t.Fatal("fat32 repair")
	}
	if Check(fat, "test") {
		t.Fatal("fat32 must verify after repair")
	}
	fat64 := makeFat([][]byte{makeRepairableSlice(cds, 2, 0)}, true)
	if _, modified, err := Repair(fat64, "test"); err != nil || !modified {
		t.Fatal("fat64 repair")
	}
	if Check(fat64, "test") {
		t.Fatal("fat64 must verify after repair")
	}
}

func TestNSpecialSlotsOverflowGuard(t *testing.T) {
	s := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0)
	cdOff := 2*4096 + 12 + 8
	putBE32(s, cdOff+24, 2) // nSpecialSlots: 2*32 = 64 > hashOffset 44
	before := append([]byte(nil), s...)
	if _, modified, _ := Repair(s, "test"); modified {
		t.Fatal("guarded CD must not be repaired")
	}
	if !bytes.Equal(s, before) {
		t.Fatal("nothing may be written")
	}
}

func TestUnsupportedHashTypeSkippedInRepair(t *testing.T) {
	s := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0)
	cdOff := 2*4096 + 12 + 8
	s[cdOff+37] = 99
	if _, modified, _ := Repair(s, "test"); modified {
		t.Fatal("unknown hashType must be left alone")
	}
}

func TestCheckFailsOnUnverifiableSignature(t *testing.T) {
	// A signature the engine cannot verify must not pass the check:
	// callers fail closed on this result and must not take "could
	// not parse" for "valid".
	mk := func() []byte { return makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0) }
	cdOff := 2*4096 + 12 + 8

	s := mk()
	s[cdOff+37] = 3 // SHA-384-shaped: unsupported
	if !Check(s, "test") {
		t.Fatal("unsupported hashType")
	}
	s = mk()
	s[cdOff+39] = 20 // unsupported page size
	if !Check(s, "test") {
		t.Fatal("pageSizeLog2")
	}
	s = mk()
	putBE32(s, cdOff+4, 0xffffffff) // cdLength out of bounds
	if !Check(s, "test") {
		t.Fatal("cdLength")
	}
	s = mk()
	putBE32(s, 2*4096, 0xdeadbeef) // SuperBlob doesn't parse
	if !Check(s, "test") {
		t.Fatal("bad SuperBlob magic")
	}
	s = mk()
	putBE32(s, 2*4096+16, 0xffffff00) // blob index out of bounds
	if !Check(s, "test") {
		t.Fatal("blob index OOB")
	}
	s = mk()
	s[cdOff+36] = 48 // hashSize inconsistent with type
	if !Check(s, "test") {
		t.Fatal("hashSize mismatch")
	}
	s = mk()
	putBE32(s, 2*4096+12+4, csMagicBlobWrapper) // CD entry -> wrapper: zero CDs
	putBE32(s, cdOff, csMagicBlobWrapper)
	if !Check(s, "test") {
		t.Fatal("zero-CodeDirectory SuperBlob")
	}
}

func TestRepairSkippingUnsupportedCDStillFailsCheck(t *testing.T) {
	// One supported CD and one with an unsupported hash type: repair
	// fixes the supported one (bytes change) but the follow-up check
	// must still fail — the unsupported CD was skipped, not verified.
	dual := []cdSpec{{csHashTypeSHA256, 32}, {csHashTypeSHA1, 20}}
	s := makeRepairableSlice(dual, 2, 0)
	sha1CdOff := 2*4096 + (12 + 2*8) + (44 + 2*32)
	s[sha1CdOff+37] = 3 // SHA-384-shaped
	if _, modified, err := Repair(s, "test"); err != nil || !modified {
		t.Fatal("supported CD must repair")
	}
	if !Check(s, "test") {
		t.Fatal("check must still flag the unverifiable CD")
	}
}

func TestNonMachOUntouched(t *testing.T) {
	s := bytes.Repeat([]byte{'x'}, 64)
	before := append([]byte(nil), s...)
	if _, modified, err := Repair(s, "test"); err != nil || modified {
		t.Fatal("non-Mach-O must be untouched")
	}
	if !bytes.Equal(s, before) {
		t.Fatal("bytes changed")
	}
}

// Both entry points parse untrusted bytes, so memory safety on
// malformed input is a correctness property. Seeded mutations and
// truncations of valid fixtures; the invariant is no panic and no
// check-mode mutation. Fixed LCG keeps the corpus reproducible.
func TestFuzzMutationsNeverPanic(t *testing.T) {
	base := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 4, 16)
	seeds := [][]byte{
		base,
		makeFat([][]byte{base, makeUnsignedSlice64()}, false),
		makeFat([][]byte{base}, true),
		makeSignedSlice64(100),
		make([]byte, 40),
	}
	rng := uint64(0x9e3779b97f4a7c15)
	next := func() uint32 {
		rng = rng*6364136223846793005 + 1442695040888963407
		return uint32(rng >> 33)
	}
	for _, seed := range seeds {
		for iter := 0; iter < 4000; iter++ {
			s := append([]byte(nil), seed...)
			if len(s) > 0 {
				pokes := 1 + int(next()%4)
				for k := 0; k < pokes; k++ {
					s[next()%uint32(len(s))] = byte(next())
				}
				if next()%4 == 0 {
					s = s[:next()%uint32(len(s)+1)]
				}
			}
			_ = Detect(s)
			check := append([]byte(nil), s...)
			_ = Check(check, "fuzz")
			if !bytes.Equal(check, s) {
				t.Fatal("check mode mutated")
			}
			repair := append([]byte(nil), s...)
			_, _, _ = Repair(repair, "fuzz") // CMS error is fine; no panic
			_ = Check(repair, "fuzz")
		}
	}
}

func TestFatSliceCodeLimitCannotCrossSliceBoundary(t *testing.T) {
	// Two slices in one fat container; slice 0's codeLimit is forged to
	// reach past its own slice into slice 1's bytes. The engine must
	// treat that CD as unverifiable — never hash across the boundary and
	// "repair" the slice against a neighbour's bytes.
	cds := []cdSpec{{csHashTypeSHA256, 32}}
	s0 := makeRepairableSlice(cds, 2, 0)
	s1 := makeRepairableSlice(cds, 2, 0)
	fat := makeFat([][]byte{s0, s1}, false)

	// Locate slice 0 inside the container and forge its codeLimit to
	// run 100 bytes past the slice's end.
	off0 := int(binary.BigEndian.Uint32(fat[8+8:]))
	cdOff := off0 + 2*4096 + 12 + 8
	putBE32(fat, cdOff+32, uint32(len(s0)+100))

	before := append([]byte(nil), fat...)
	_, _, err := Repair(fat, "test")
	if err != nil {
		t.Fatal(err)
	}
	// Slice 0's forged CD must not have been "repaired" using slice 1's
	// bytes: its hash slots must be untouched (still the stale zeros).
	slot0 := fat[cdOff+44 : cdOff+44+32]
	if !bytes.Equal(slot0, before[cdOff+44:cdOff+44+32]) {
		t.Fatal("engine hashed across a fat slice boundary and rewrote the forged CD's slots")
	}
	// And check must fail closed on it.
	fresh := append([]byte(nil), before...)
	if !Check(fresh, "test") {
		t.Fatal("cross-boundary codeLimit must be unverifiable")
	}
}

// makeSpecialSlotSlice builds a signed slice with nSpecial special-slot
// hashes before the code slots (hashOffset > cdHeaderSize), the shape
// codesign(1) emits for real binaries (Info.plist, requirements, ...).
// Code slots are zeroed (stale); special slots hold arbitrary bytes the
// engine must preserve — they hash other blobs, not code pages.
func makeSpecialSlotSlice(nSpecial, pages int) []byte {
	const headerSize, lcSize, pageSize, hashSize = 32, 16, 4096, 32
	sigOff := pages * pageSize
	sbHeader := 12 + 1*8
	hashOffset := 44 + nSpecial*hashSize
	cdLen := hashOffset + pages*hashSize
	sigSize := sbHeader + cdLen
	s := bytes.Repeat([]byte{'A'}, sigOff+sigSize)

	putLE32(s, 0, machMagic64)
	putLE32(s, 16, 1)
	putLE32(s, 20, lcSize)
	putLE32(s, headerSize+0, lcCodeSignature)
	putLE32(s, headerSize+4, lcSize)
	putLE32(s, headerSize+8, uint32(sigOff))
	putLE32(s, headerSize+12, uint32(sigSize))

	putBE32(s, sigOff+0, csMagicEmbeddedSignature)
	putBE32(s, sigOff+4, uint32(sigSize))
	putBE32(s, sigOff+8, 1)
	putBE32(s, sigOff+12, 0) // CSSLOT_CODEDIRECTORY
	putBE32(s, sigOff+16, uint32(sbHeader))

	cdOff := sigOff + sbHeader
	putBE32(s, cdOff+0, csMagicCodeDirectory)
	putBE32(s, cdOff+4, uint32(cdLen))
	putBE32(s, cdOff+16, uint32(hashOffset))
	putBE32(s, cdOff+24, uint32(nSpecial))
	putBE32(s, cdOff+28, uint32(pages))
	putBE32(s, cdOff+32, uint32(sigOff)) // codeLimit
	s[cdOff+36] = 32
	s[cdOff+37] = csHashTypeSHA256
	s[cdOff+39] = 12
	// Special slots: fill with a recognizable pattern to detect any
	// write; code slots zeroed (stale).
	for j := 0; j < nSpecial*hashSize; j++ {
		s[cdOff+44+j] = 0xEE
	}
	for j := 0; j < pages*hashSize; j++ {
		s[cdOff+hashOffset+j] = 0
	}
	return s
}

func TestSpecialSlotsPreservedAcrossRepair(t *testing.T) {
	const nSpecial, pages, hashSize = 3, 2, 32
	s := makeSpecialSlotSlice(nSpecial, pages)
	if Detect(s) != AdHoc {
		t.Fatal("special-slot fixture must be AdHoc")
	}
	if !Check(s, "test") {
		t.Fatal("zeroed code slots must be stale")
	}
	cdOff := pages*4096 + 12 + 8
	specialBefore := append([]byte(nil), s[cdOff+44:cdOff+44+nSpecial*hashSize]...)

	changed, modified, err := Repair(s, "test")
	if err != nil || !modified {
		t.Fatalf("repair: %v %v", modified, err)
	}
	// Special slots untouched, byte for byte.
	if !bytes.Equal(s[cdOff+44:cdOff+44+nSpecial*hashSize], specialBefore) {
		t.Fatal("repair rewrote special slots; it may only touch code slots")
	}
	// Every journaled change lies inside the code-slot region.
	slotsStart := int64(cdOff + 44 + nSpecial*hashSize)
	slotsEnd := slotsStart + int64(pages*hashSize)
	for _, c := range changed {
		if c.Offset < slotsStart || c.Offset+int64(len(c.Old)) > slotsEnd {
			t.Fatalf("change at %d outside code-slot region [%d,%d)", c.Offset, slotsStart, slotsEnd)
		}
	}
	// And the repaired code slots verify: valid per engine and oracle.
	if Check(s, "test") {
		t.Fatal("must verify after repair")
	}
	if got := oracleStaleCount(t, s); got != 0 {
		t.Fatalf("oracle sees %d stale slots after special-slot repair", got)
	}
}

func TestRepairFatWithCMSSliceTouchesNothing(t *testing.T) {
	// Repair's contract: "returns ErrCMSRepair without touching a byte
	// if ANY slice carries a non-empty CMS signature". The repairable
	// slice comes FIRST here, so a walker that repairs as it goes would
	// modify slice 0 before discovering slice 1's CMS blob.
	adhoc := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 0)
	cms := makeRepairableSlice([]cdSpec{{csHashTypeSHA256, 32}}, 2, 100)
	fat := makeFat([][]byte{adhoc, cms}, false)
	before := append([]byte(nil), fat...)

	changed, modified, err := Repair(fat, "test")
	if err == nil {
		t.Fatal("fat container with a CMS slice must refuse repair")
	}
	if modified || len(changed) != 0 {
		t.Fatalf("refusal must report no modification: modified=%v changes=%d", modified, len(changed))
	}
	if !bytes.Equal(fat, before) {
		t.Fatal("refusal touched bytes: the repairable slice was modified before the CMS slice was seen")
	}
}

// TestDetectThin32BitHeader ports the C++ thin32BitHeader case: a
// 32-bit mach_header (28 bytes, MH_MAGIC) with an LC_CODE_SIGNATURE
// whose SuperBlob is out of bounds is still detected as signed
// (fail toward detection). The 32-bit header path is otherwise
// exercised only by real binaries.
func TestDetectThin32BitHeader(t *testing.T) {
	s := make([]byte, 28+16)
	putLE32(s, 0, machMagic32)
	putLE32(s, 16, 1)  // ncmds
	putLE32(s, 20, 16) // sizeofcmds
	putLE32(s, 28+0, lcCodeSignature)
	putLE32(s, 28+4, 16)
	putLE32(s, 28+8, 0xffff0000) // dataoff far beyond EOF
	putLE32(s, 28+12, 64)
	if Detect(s) != AdHoc {
		t.Fatal("32-bit signed header with OOB SuperBlob must detect AdHoc")
	}
	// And check must flag it (present signature, unverifiable).
	if !Check(s, "test") {
		t.Fatal("32-bit unverifiable signature must fail check")
	}
}

// TestDetectBigJavaClassFile ports the C++ big-class-file case: a large
// file sharing the fat magic (Java .class, version field read as
// nfat_arch) has room for the phantom arch table, but its garbage
// "slices" carry no Mach-O magic, so it is None. The small class file
// (rejected earlier by the arch-array bounds check) is a different
// path, covered by TestDetectJavaClassFile.
func TestDetectBigJavaClassFile(t *testing.T) {
	big := bytes.Repeat([]byte{0x5a}, 8192)
	putBE32(big, 0, 0xcafebabe)
	putBE32(big, 4, 65) // major version 65 (Java 21) read as nfat_arch
	if Detect(big) != None {
		t.Fatal("big class file: phantom slices carry no Mach-O magic, must be None")
	}
	if Check(big, "test") {
		t.Fatal("big class file must not be flagged")
	}
}
