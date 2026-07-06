package nixstore

import "testing"

func TestNixBase32(t *testing.T) {
	// Ground truth from `nix hash convert --to nix32` on a real path's
	// SRI NAR hash (fish-4.7.1-doc): the sha256 digest of that NAR, in
	// nix-base32, is the string below. This pins the encoder against
	// Nix's own output.
	// sha256-yKYGaeC9CQnaq4Pp56iUHCKj573nyFiW0IH/IVJpYQQ= ->
	want := "0131d5923zw1s2b5ij77ppks68hwjjlfgsc3mgd0j2dxw1lhd9n8"
	// The 32-byte digest that base64-decodes from the SRI above.
	digest := []byte{
		0xc8, 0xa6, 0x06, 0x69, 0xe0, 0xbd, 0x09, 0x09,
		0xda, 0xab, 0x83, 0xe9, 0xe7, 0xa8, 0x94, 0x1c,
		0x22, 0xa3, 0xe7, 0xbd, 0xe7, 0xc8, 0x58, 0x96,
		0xd0, 0x81, 0xff, 0x21, 0x52, 0x69, 0x61, 0x04,
	}
	if got := nixBase32(digest); got != want {
		t.Errorf("nixBase32 = %q, want %q", got, want)
	}
	if got := NarHash4Test(digest); got != "sha256:"+want {
		t.Errorf("NarHash prefix = %q", got)
	}
}

// NarHash4Test formats a precomputed digest the way NarHash does, so the
// test can pin the encoding without re-hashing a NAR.
func NarHash4Test(digest []byte) string {
	return "sha256:" + nixBase32(digest)
}
