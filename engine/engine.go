// Package engine detects, verifies, and repairs Mach-O code-signature
// page hashes that no longer match the file's contents — the state a
// Nix store-path hash rewrite (or a producer bug like `bun --compile`)
// leaves a signed binary in. macOS kills such binaries at first
// page-in with SIGKILL (cs_invalid_page).
//
// The repair is slot-surgical and deterministic: only hash slots whose
// stored value disagrees with the page contents are rewritten, and
// every other byte — the linker-signed flag, the page size, the
// identifier, the CMS wrapper — is preserved. The same input bytes
// always yield the same output bytes.
//
// Never repaired: signatures carrying a non-empty CMS (PKCS#7) blob
// (Developer ID / App Store — the certificate chain commits to the
// CodeDirectory, so only the original signer can fix those).
//
// This is a Go port of the engine validated on the NixOS/nix#15638
// branch (30 unit tests, mutation fuzzing, ASan/UBSan, and a 10/10
// real-binary validation against cache.nixos.org artifacts with an
// independent from-scratch verifier).
package engine

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// Mach-O and code-signing constants, mirrored from Apple's
// <mach-o/loader.h>, <mach-o/fat.h> and xnu's bsd/sys/codesign.h.
// Vendored so detection works identically on every platform.
const (
	machMagic32 = 0xfeedface // MH_MAGIC
	machMagic64 = 0xfeedfacf // MH_MAGIC_64
	fatMagic32  = 0xcafebabe // FAT_MAGIC (big-endian on disk)
	fatMagic64  = 0xcafebabf // FAT_MAGIC_64

	lcCodeSignature = 0x1d // LC_CODE_SIGNATURE

	csMagicEmbeddedSignature = 0xfade0cc0 // CSMAGIC_EMBEDDED_SIGNATURE
	csMagicCodeDirectory     = 0xfade0c02 // CSMAGIC_CODEDIRECTORY
	csMagicBlobWrapper       = 0xfade0b01 // CSMAGIC_BLOBWRAPPER
	csSlotSignature          = 0x10000    // CSSLOT_SIGNATURESLOT

	csHashTypeSHA1   = 1
	csHashTypeSHA256 = 2
	csHashSizeSHA1   = 20
	csHashSizeSHA256 = 32

	// Apple emits 12 (4 KiB) for linker-signed binaries and 14
	// (16 KiB) for codesign(1).
	maxPageSizeLog2 = 16

	machHeaderSize32       = 28
	machHeaderSize64       = 32
	fatHeaderSize          = 8
	fatArchSize32          = 20
	fatArchSize64          = 32
	loadCommandSize        = 8
	linkeditDataCmdSize    = 16
	superBlobHeaderSize    = 12
	blobIndexSize          = 8
	cdHeaderSize           = 44 // through pageSizeLog2; we never read past byte 40
	maxNFatArch            = 128
	maxSuperBlobCount      = 16
)

// Kind classifies the code signature a Mach-O file carries.
type Kind int

const (
	// None: no LC_CODE_SIGNATURE load command in any slice.
	None Kind = iota
	// AdHoc: a signature without an embedded CMS blob — ld's
	// linker-signed ad-hoc signature or `codesign --sign -`.
	// Deterministically regenerable from the file contents alone.
	AdHoc
	// CMS: a signature carrying a non-empty PKCS#7 blob (Developer
	// ID, App Store). Cannot be regenerated without the signer.
	CMS
)

func (k Kind) String() string {
	switch k {
	case AdHoc:
		return "ad-hoc"
	case CMS:
		return "CMS (Developer ID)"
	default:
		return "unsigned"
	}
}

// ErrCMSRepair is returned when repair is requested on a slice whose
// signature carries a non-empty CMS blob.
type ErrCMSRepair struct{ Path string }

func (e *ErrCMSRepair) Error() string {
	return fmt.Sprintf("%s carries a CMS signature (Developer ID); its page hashes cannot be repaired without invalidating the signer's certificate chain", e.Path)
}

func rdLE32(b []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(b[off : off+4])
}

func rdBE32(b []byte, off int) uint32 {
	return binary.BigEndian.Uint32(b[off : off+4])
}

func rdBE64(b []byte, off int) uint64 {
	return binary.BigEndian.Uint64(b[off : off+8])
}

// HasMachOMagic reports whether the first four bytes identify a
// possible Mach-O (thin, either width, or a fat container). Callers
// peek a fixed 4-byte prefix before reading files whole.
func HasMachOMagic(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	le := binary.LittleEndian.Uint32(p)
	be := binary.BigEndian.Uint32(p)
	return le == machMagic32 || le == machMagic64 || be == fatMagic32 || be == fatMagic64
}

// validSliceBounds: a fat slice is valid if it fits strictly between
// the fat_arch array and EOF, and has non-zero size. Subtraction form
// so the addition can't wrap on fat64's u64 offset/size fields. The
// detector and the repair walker share this rule: a slice one walks
// and the other skips could pass a check it was never given.
func validSliceBounds(sliceOff, sliceSize, archArrayEnd, fileSize uint64) bool {
	if sliceSize == 0 || sliceOff < archArrayEnd || sliceOff >= fileSize {
		return false
	}
	return sliceSize <= fileSize-sliceOff
}

// findSignature walks a slice's load commands for LC_CODE_SIGNATURE.
// Returns (sigOff, sigSize, true) relative to sliceBase, or ok=false
// on malformed or unsigned slices.
func findSignature(data []byte, sliceBase int) (uint32, uint32, bool) {
	size := len(data)
	if sliceBase+machHeaderSize32 > size {
		return 0, 0, false
	}
	magic := rdLE32(data, sliceBase)
	var headerSize int
	switch magic {
	case machMagic64:
		headerSize = machHeaderSize64
	case machMagic32:
		headerSize = machHeaderSize32
	default:
		return 0, 0, false
	}
	if sliceBase+headerSize > size {
		return 0, 0, false
	}
	ncmds := int(rdLE32(data, sliceBase+16))
	sizeofcmds := int(rdLE32(data, sliceBase+20))
	if sizeofcmds < 0 || sliceBase+headerSize+sizeofcmds > size {
		return 0, 0, false
	}
	lcOff := sliceBase + headerSize
	lcEnd := lcOff + sizeofcmds
	for i := 0; i < ncmds; i++ {
		if lcOff+loadCommandSize > lcEnd {
			return 0, 0, false
		}
		cmd := rdLE32(data, lcOff)
		cmdsize := int(rdLE32(data, lcOff+4))
		if cmdsize < loadCommandSize || lcOff+cmdsize > lcEnd {
			return 0, 0, false
		}
		if cmd == lcCodeSignature {
			if cmdsize < linkeditDataCmdSize {
				return 0, 0, false
			}
			return rdLE32(data, lcOff+8), rdLE32(data, lcOff+12), true
		}
		lcOff += cmdsize
	}
	return 0, 0, false
}

// detectSlice classifies the signature (if any) of one slice.
func detectSlice(data []byte, sliceBase int) Kind {
	sigOff, sigSize, ok := findSignature(data, sliceBase)
	if !ok {
		return None
	}
	// The signature is present. Peek into the SuperBlob to tell an
	// ad-hoc signature from a CMS-signed one; if the blob doesn't
	// parse, report AdHoc — a rewrite would still invalidate it.
	size := len(data)
	sbAbs := sliceBase + int(sigOff)
	if sigSize < superBlobHeaderSize || sbAbs+int(sigSize) > size || sbAbs+int(sigSize) < sbAbs {
		return AdHoc
	}
	if rdBE32(data, sbAbs) != csMagicEmbeddedSignature {
		return AdHoc
	}
	sbCount := rdBE32(data, sbAbs+8)
	if sbCount > maxSuperBlobCount {
		return AdHoc
	}
	for bi := 0; bi < int(sbCount); bi++ {
		entryOff := sbAbs + superBlobHeaderSize + bi*blobIndexSize
		if entryOff+blobIndexSize > sbAbs+int(sigSize) {
			break
		}
		if rdBE32(data, entryOff) != csSlotSignature {
			continue
		}
		blobRel := rdBE32(data, entryOff+4)
		blobAbs := sbAbs + int(blobRel)
		if int(blobRel) > int(sigSize) || blobAbs+8 > sbAbs+int(sigSize) {
			continue
		}
		if rdBE32(data, blobAbs) != csMagicBlobWrapper {
			continue
		}
		// An empty 8-byte wrapper is what ad-hoc codesign(1)
		// leaves in place; anything larger is a PKCS#7 chain.
		if rdBE32(data, blobAbs+4) > 8 {
			return CMS
		}
	}
	return AdHoc
}

// Detect classifies contents as a Mach-O file carrying a code
// signature. For fat containers the strongest kind across slices is
// returned. Purely content-based — identical on every platform.
func Detect(contents []byte) Kind {
	if len(contents) < machHeaderSize32 {
		return None
	}
	magicLE := rdLE32(contents, 0)
	magicBE := rdBE32(contents, 0)

	// Byte-swapped magics (MH_CIGAM etc.) are deliberately not
	// handled: they only occur in PowerPC-era big-endian binaries.
	if magicLE == machMagic32 || magicLE == machMagic64 {
		return detectSlice(contents, 0)
	}
	if magicBE != fatMagic32 && magicBE != fatMagic64 {
		return None
	}
	is64 := magicBE == fatMagic64
	archSize := fatArchSize32
	if is64 {
		archSize = fatArchSize64
	}
	nfat := rdBE32(contents, 4)
	if nfat == 0 || nfat > maxNFatArch {
		return None
	}
	archArrayEnd := uint64(fatHeaderSize) + uint64(nfat)*uint64(archSize)
	if archArrayEnd > uint64(len(contents)) {
		return None
	}
	result := None
	for i := 0; i < int(nfat); i++ {
		archOff := fatHeaderSize + i*archSize
		var sliceOff, sliceSize uint64
		if is64 {
			sliceOff = rdBE64(contents, archOff+8)
			sliceSize = rdBE64(contents, archOff+16)
		} else {
			sliceOff = uint64(rdBE32(contents, archOff+8))
			sliceSize = uint64(rdBE32(contents, archOff+12))
		}
		if !validSliceBounds(sliceOff, sliceSize, archArrayEnd, uint64(len(contents))) {
			continue
		}
		if k := detectSlice(contents, int(sliceOff)); k > result {
			result = k
		}
	}
	return result
}

// fixupSlice recomputes stale page-hash slots of one slice. In check
// mode (write=false) it only reports; a signature that is present but
// cannot be verified (unsupported hash type, malformed CodeDirectory)
// counts as stale, since callers that fail closed on this result must
// not take "could not parse" for "valid". Returns (modified, err);
// err is non-nil only for CMS-repair refusal.
//
// When write=true, changed is appended with one Change per rewritten
// slot (for undo journaling).
func fixupSlice(data []byte, sliceBase int, path string, write bool, changed *[]Change) (bool, error) {
	sigOff, sigSize, ok := findSignature(data, sliceBase)
	if !ok {
		return false, nil
	}
	size := len(data)
	sbAbs := sliceBase + int(sigOff)

	// A signature is present from here on. Anything that prevents
	// verifying it counts as suspect in check mode.
	unverifiable := false
	if sigSize < superBlobHeaderSize || sbAbs+int(sigSize) > size || sbAbs+int(sigSize) < sbAbs {
		return !write, nil
	}
	if rdBE32(data, sbAbs) != csMagicEmbeddedSignature {
		return !write, nil
	}
	sbCount := rdBE32(data, sbAbs+8)
	if sbCount > maxSuperBlobCount {
		return !write, nil
	}

	// Pre-scan for a non-empty CMS blob before repairing. In check
	// mode a CMS slice is verified like any other — stale hashes
	// under a CMS signature are still stale.
	if write {
		for bi := 0; bi < int(sbCount); bi++ {
			entryOff := sbAbs + superBlobHeaderSize + bi*blobIndexSize
			if entryOff+blobIndexSize > sbAbs+int(sigSize) {
				break
			}
			if rdBE32(data, entryOff) != csSlotSignature {
				continue
			}
			blobRel := rdBE32(data, entryOff+4)
			blobAbs := sbAbs + int(blobRel)
			if int(blobRel) > int(sigSize) || blobAbs+8 > sbAbs+int(sigSize) {
				continue
			}
			if rdBE32(data, blobAbs) != csMagicBlobWrapper {
				continue
			}
			if rdBE32(data, blobAbs+4) > 8 {
				return false, &ErrCMSRepair{Path: path}
			}
		}
	}

	modified := false
	anyCodeDirectory := false

	// Process every CodeDirectory: pre-2016 binaries carry SHA-1 +
	// SHA-256 alternates in one SuperBlob and the kernel validates
	// every one at page-in, so fixing only one leaves the binary
	// broken.
	for bi := 0; bi < int(sbCount); bi++ {
		entryOff := sbAbs + superBlobHeaderSize + bi*blobIndexSize
		if entryOff+blobIndexSize > sbAbs+int(sigSize) {
			unverifiable = true
			break
		}
		blobRel := rdBE32(data, entryOff+4)
		blobAbs := sbAbs + int(blobRel)
		if int(blobRel) > int(sigSize) || blobAbs+8 > sbAbs+int(sigSize) {
			unverifiable = true
			continue
		}
		if rdBE32(data, blobAbs) != csMagicCodeDirectory {
			continue
		}
		anyCodeDirectory = true

		if blobAbs+cdHeaderSize > sbAbs+int(sigSize) {
			unverifiable = true
			continue
		}
		cdLength := rdBE32(data, blobAbs+4)
		if cdLength < cdHeaderSize || cdLength > sigSize || blobAbs+int(cdLength) > sbAbs+int(sigSize) {
			unverifiable = true
			continue
		}
		hashOffset := rdBE32(data, blobAbs+16)
		nSpecialSlots := rdBE32(data, blobAbs+24)
		nCodeSlots := rdBE32(data, blobAbs+28)
		codeLimit := rdBE32(data, blobAbs+32)
		hashSize := int(data[blobAbs+36])
		hashType := int(data[blobAbs+37])
		pageSizeLog2 := int(data[blobAbs+39])

		var newHash func() hash.Hash
		var expectedHashSize int
		switch hashType {
		case csHashTypeSHA256:
			newHash, expectedHashSize = sha256.New, csHashSizeSHA256
		case csHashTypeSHA1:
			newHash, expectedHashSize = sha1.New, csHashSizeSHA1
		default:
			unverifiable = true
			continue
		}
		if hashSize != expectedHashSize {
			unverifiable = true
			continue
		}
		if pageSizeLog2 == 0 || pageSizeLog2 > maxPageSizeLog2 {
			unverifiable = true
			continue
		}
		// Special slots hash other blobs at negative indices from
		// hashOffset, so they must fit below the code-slot region.
		if uint64(nSpecialSlots)*uint64(hashSize) > uint64(hashOffset) {
			unverifiable = true
			continue
		}
		pageSize := 1 << pageSizeLog2
		slotsAbs := blobAbs + int(hashOffset)
		slotsEnd := uint64(slotsAbs) + uint64(nCodeSlots)*uint64(hashSize)
		if hashOffset > cdLength || slotsEnd > uint64(blobAbs)+uint64(cdLength) || slotsEnd > uint64(size) {
			unverifiable = true
			continue
		}
		for i := 0; i < int(nCodeSlots); i++ {
			pageStart := uint64(sliceBase) + uint64(i)*uint64(pageSize)
			pageEnd := uint64(sliceBase) + uint64(i+1)*uint64(pageSize)
			if limit := uint64(sliceBase) + uint64(codeLimit); pageEnd > limit {
				pageEnd = limit
			}
			if pageEnd > uint64(size) || pageEnd < pageStart {
				unverifiable = true
				continue
			}
			h := newHash()
			h.Write(data[pageStart:pageEnd])
			sum := h.Sum(nil)
			slot := slotsAbs + i*hashSize
			if !bytesEqual(data[slot:slot+hashSize], sum) {
				if write {
					if changed != nil {
						old := make([]byte, hashSize)
						copy(old, data[slot:slot+hashSize])
						*changed = append(*changed, Change{Offset: int64(slot), Old: old})
					}
					copy(data[slot:slot+hashSize], sum)
				}
				modified = true
			}
		}
	}

	// A SuperBlob that parses but contains no CodeDirectory at all
	// declares a signature there is no way to verify.
	if !anyCodeDirectory {
		unverifiable = true
	}
	return modified || (!write && unverifiable), nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Change records one slot rewrite for byte-exact undo.
type Change struct {
	Offset int64
	Old    []byte
}

// walk applies fixupSlice across the container (thin or fat).
func walk(contents []byte, path string, write bool, changed *[]Change) (bool, error) {
	if len(contents) < machHeaderSize32 {
		return false, nil
	}
	magicLE := rdLE32(contents, 0)
	magicBE := rdBE32(contents, 0)
	if magicLE == machMagic32 || magicLE == machMagic64 {
		return fixupSlice(contents, 0, path, write, changed)
	}
	if magicBE != fatMagic32 && magicBE != fatMagic64 {
		return false, nil
	}
	is64 := magicBE == fatMagic64
	archSize := fatArchSize32
	if is64 {
		archSize = fatArchSize64
	}
	nfat := rdBE32(contents, 4)
	if nfat == 0 || nfat > maxNFatArch {
		return false, nil
	}
	archArrayEnd := uint64(fatHeaderSize) + uint64(nfat)*uint64(archSize)
	if archArrayEnd > uint64(len(contents)) {
		return false, nil
	}
	modified := false
	for i := 0; i < int(nfat); i++ {
		archOff := fatHeaderSize + i*archSize
		var sliceOff, sliceSize uint64
		if is64 {
			sliceOff = rdBE64(contents, archOff+8)
			sliceSize = rdBE64(contents, archOff+16)
		} else {
			sliceOff = uint64(rdBE32(contents, archOff+8))
			sliceSize = uint64(rdBE32(contents, archOff+12))
		}
		if !validSliceBounds(sliceOff, sliceSize, archArrayEnd, uint64(len(contents))) {
			continue
		}
		m, err := fixupSlice(contents, int(sliceOff), path, write, changed)
		if err != nil {
			return modified, err
		}
		modified = modified || m
	}
	return modified, nil
}

// Check reports whether any signature in contents is stale or cannot
// be verified. It never writes. path is used in diagnostics only.
func Check(contents []byte, path string) bool {
	stale, _ := walk(contents, path, false, nil)
	return stale
}

// Repair recomputes stale page-hash slots in place. It returns the
// list of slot changes (for undo journaling) and whether anything was
// modified. Returns ErrCMSRepair without touching a byte if any slice
// carries a non-empty CMS signature.
func Repair(contents []byte, path string) (changed []Change, modified bool, err error) {
	modified, err = walk(contents, path, true, &changed)
	return changed, modified, err
}
