package sequencefunc

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

// deriveBlock wipes the hash of a long value, but must never touch the
// caller's value, and its output must be unchanged.
func TestDeriveBlockWipesOnlyItsOwnCopies(t *testing.T) {
	for _, h := range []func() hash.Hash{sha256.New, sha512.New} {
		bs := h().BlockSize()
		for n := 0; n <= 3*bs; n++ {
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(i%251 + 1)
			}
			orig := bytes.Clone(data)

			// Independent computation of the expected block.
			reduced := orig
			if n > bs {
				d := h()
				d.Write(orig)
				reduced = d.Sum(nil)
			}
			want := make([]byte, bs*max(1, (len(reduced)+bs-1)/bs))
			copy(want, reduced)
			want[0] ^= TWEAK_INNER

			got := deriveBlock(data, h, TWEAK_INNER)
			if !bytes.Equal(got, want) {
				t.Fatalf("block size %d, len %d: wrong block", bs, n)
			}
			if !bytes.Equal(data, orig) {
				t.Fatalf("block size %d, len %d: caller's value was modified", bs, n)
			}
		}
	}
}
