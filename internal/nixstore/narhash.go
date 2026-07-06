package nixstore

import (
	"crypto/sha256"
	"fmt"
)

// nixBase32Alphabet is Nix's own base-32 alphabet (omits e o u t to
// avoid rude words and digit/letter confusion), used for store hashes.
const nixBase32Alphabet = "0123456789abcdfghijklmnpqrsvwxyz"

// nixBase32 encodes `data` in Nix's base-32, least-significant group
// first — the exact scheme `nix-store` prints NAR hashes in.
func nixBase32(data []byte) string {
	length := (len(data)*8-1)/5 + 1
	out := make([]byte, length)
	for n := 0; n < length; n++ {
		b := n * 5
		i := b / 8
		j := b % 8
		c := data[i] >> uint(j)
		if i+1 < len(data) {
			c |= data[i+1] << uint(8-j)
		}
		out[length-1-n] = nixBase32Alphabet[c&0x1f]
	}
	return string(out)
}

// NarHash returns the `sha256:<nix-base32>` NAR hash of `nar`, matching
// what Nix records for a path.
func NarHash(nar []byte) string {
	sum := sha256.Sum256(nar)
	return fmt.Sprintf("sha256:%s", nixBase32(sum[:]))
}
