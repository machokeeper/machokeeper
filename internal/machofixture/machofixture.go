// Package machofixture builds in-memory Mach-O byte blobs for tests of
// the higher layers (doctor, hook, wrap) that need real broken,
// repairable, and unrepairable signed binaries without a compiler or a
// darwin host. The constants are vendored independently of the engine,
// so a fixture and the engine under test share no source — the same
// independence the Python oracle has.
package machofixture

import "encoding/binary"

const (
	machMagic64              = 0xfeedfacf
	lcCodeSignature          = 0x1d
	csMagicEmbeddedSignature = 0xfade0cc0
	csMagicCodeDirectory     = 0xfade0c02
	csMagicBlobWrapper       = 0xfade0b01
	csSlotSignature          = 0x10000
	csHashTypeSHA256         = 2
	csHashSizeSHA256         = 32
)

func le32(b []byte, o int, v uint32) { binary.LittleEndian.PutUint32(b[o:], v) }
func be32(b []byte, o int, v uint32) { binary.BigEndian.PutUint32(b[o:], v) }

// Repairable returns a thin ad-hoc-signed Mach-O with `pages` code
// pages whose SHA-256 hash slots are all zero (stale). engine.Detect
// classifies it AdHoc, engine.Check reports it stale, and engine.Repair
// fixes it — so it is a valid "broken but repairable" fixture.
func Repairable(pages int) []byte {
	return build(pages, 0)
}

// CMS returns the same shape but with a non-empty CMS blob wrapper
// (Developer-ID style): engine.Detect classifies it Cms and repair
// refuses it.
func CMS(pages int) []byte {
	return build(pages, 64)
}

// Unsigned returns a Mach-O with a single non-signature load command.
func Unsigned() []byte {
	const headerSize, lcSize = 32, 16
	s := make([]byte, headerSize+lcSize)
	le32(s, 0, machMagic64)
	le32(s, 16, 1)
	le32(s, 20, lcSize)
	le32(s, headerSize+0, 0x32) // LC_SOURCE_VERSION
	le32(s, headerSize+4, lcSize)
	return s
}

func build(pages, cmsLen int) []byte {
	const headerSize, lcSize, pageSize = 32, 16, 4096
	sigOff := pages * pageSize
	nCodeSlots := pages
	haveCMS := cmsLen > 0
	nBlobs := 1
	if haveCMS {
		nBlobs = 2
	}
	sbHeader := 12 + nBlobs*8
	cdLen := 44 + nCodeSlots*csHashSizeSHA256
	sigSize := sbHeader + cdLen
	if haveCMS {
		sigSize += cmsLen
	}
	s := make([]byte, sigOff+sigSize)
	for i := range s[:sigOff] {
		s[i] = 'A'
	}

	le32(s, 0, machMagic64)
	le32(s, 16, 1)
	le32(s, 20, lcSize)
	le32(s, headerSize+0, lcCodeSignature)
	le32(s, headerSize+4, lcSize)
	le32(s, headerSize+8, uint32(sigOff))
	le32(s, headerSize+12, uint32(sigSize))

	be32(s, sigOff+0, csMagicEmbeddedSignature)
	be32(s, sigOff+4, uint32(sigSize))
	be32(s, sigOff+8, uint32(nBlobs))
	be32(s, sigOff+12, 0) // CSSLOT_CODEDIRECTORY
	be32(s, sigOff+16, uint32(sbHeader))
	if haveCMS {
		be32(s, sigOff+20, csSlotSignature)
		be32(s, sigOff+24, uint32(sbHeader+cdLen))
	}

	cdOff := sigOff + sbHeader
	be32(s, cdOff+0, csMagicCodeDirectory)
	be32(s, cdOff+4, uint32(cdLen))
	be32(s, cdOff+16, 44)                 // hashOffset
	be32(s, cdOff+24, 0)                  // nSpecialSlots
	be32(s, cdOff+28, uint32(nCodeSlots)) // nCodeSlots
	be32(s, cdOff+32, uint32(sigOff))     // codeLimit
	s[cdOff+36] = csHashSizeSHA256
	s[cdOff+37] = csHashTypeSHA256
	s[cdOff+39] = 12 // pageSizeLog2 (4096)
	// slots left zero == stale

	if haveCMS {
		cmsOff := cdOff + cdLen
		be32(s, cmsOff+0, csMagicBlobWrapper)
		be32(s, cmsOff+4, uint32(cmsLen))
	}
	return s
}
