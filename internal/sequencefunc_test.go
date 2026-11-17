package sequencefunc

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

func TestBlockSize(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil))
	if eFunc.BlockSize() != sha256.BlockSize {
		t.Fatalf("Block size mismatch for SHA256")
	}

	eFunc = New(sha512.New, 0, []byte(nil))
	if eFunc.BlockSize() != sha512.BlockSize {
		t.Fatalf("Block size mismatch for SHA512")
	}
}

func TestSize(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil))
	if eFunc.Size() != sha256.Size {
		t.Fatalf("Size mismatch for SHA256")
	}

	eFunc = New(sha512.New, 0, []byte(nil))
	if eFunc.Size() != sha512.Size {
		t.Fatalf("Size mismatch for SHA512")
	}
}

func TestAdd(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil))
	eFunc.Add([]byte(nil))

}

func TestSum(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil))
	eFunc.Add([]byte(nil))
	sum := eFunc.Result()
	if bytes.Equal(sum, make([]byte, 32)) {
		t.Fatalf("Incorrect sum")
	}
}

func TestDeriveBlock(t *testing.T) {
	shortInput := make([]byte, 8)
	longInput := make([]byte, 256)

	longHash := sha256.Sum256(longInput)

	expectedShort := make([]byte, sha256.New().BlockSize())
	expectedLong := padData(longHash[:], sha256.BlockSize)

	shortDerived := deriveBlock(shortInput, sha256.New, 0x00)
	longDerived := deriveBlock(longInput, sha256.New, 0x00)

	if !bytes.Equal(expectedLong, longDerived) {
		t.Fatalf("Long derivation failed")
	}
	if !bytes.Equal(expectedShort, shortDerived) {
		t.Fatalf("Short derivation failed")
	}
}

// patterned returns n non-zero bytes, so that a write of zeroes or an XOR with
// a tweak is always visible.
func patterned(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131+7) | 0x01
	}
	return b
}

// deriveBlock must never write to the memory it is given, whatever the
// input's length (shorter than, equal to or longer than the block) and
// whether or not the slice has spare capacity after it. Its result must not
// share memory with the input either.
func TestDeriveBlockDoesNotTouchInput(t *testing.T) {
	hashes := map[string]func() hash.Hash{"sha256": sha256.New, "sha512": sha512.New}
	for name, h := range hashes {
		blockSize := h().BlockSize()
		for n := 0; n <= 2*blockSize+1; n++ {
			for _, tweak := range []byte{TWEAK_INNER, TWEAK_OUTER} {
				// The input is the first n bytes of a larger buffer, so it has
				// blockSize bytes of spare capacity.
				backing := patterned(n + blockSize)
				input := backing[:n]
				before := bytes.Clone(backing)

				derived := deriveBlock(input, h, tweak)

				if !bytes.Equal(backing, before) {
					t.Fatalf("%s, %d-byte input, tweak %#x: input memory was modified", name, n, tweak)
				}
				if want := expectedBlock(before[:n], h, tweak); !bytes.Equal(derived, want) {
					t.Fatalf("%s, %d-byte input, tweak %#x: wrong derived block", name, n, tweak)
				}
				for i := range derived {
					derived[i] ^= 0xff
				}
				if !bytes.Equal(backing, before) {
					t.Fatalf("%s, %d-byte input, tweak %#x: derived block shares memory with the input", name, n, tweak)
				}
			}
		}
	}
}

// expectedBlock computes deriveBlock's result independently: hash the input
// if it is longer than the block, zero-pad it to the block size, and XOR the
// tweak into the first byte.
func expectedBlock(input []byte, h func() hash.Hash, tweak byte) []byte {
	blockSize := h().BlockSize()
	if len(input) > blockSize {
		d := h()
		d.Write(input)
		input = d.Sum(nil)
	}
	block := make([]byte, blockSize)
	copy(block, input)
	block[0] ^= tweak
	return block
}

// New must leave the caller's key untouched, for any key length, and the
// result must not depend on what surrounds the key in memory.
func TestNewDoesNotTouchKey(t *testing.T) {
	for _, n := range []int{32, 63, 64, 65, 128} {
		backing := patterned(n + 64)
		key := backing[:n]
		before := bytes.Clone(backing)

		f := New(sha256.New, FUNCTION_ID_MAC, key)
		f.Add([]byte("abc"))
		got := f.Result()

		if !bytes.Equal(backing, before) {
			t.Fatalf("%d-byte key: key memory was modified", n)
		}
		g := New(sha256.New, FUNCTION_ID_MAC, bytes.Clone(before[:n]))
		g.Add([]byte("abc"))
		if !bytes.Equal(got, g.Result()) {
			t.Fatalf("%d-byte key: result depends on the key's backing array", n)
		}
	}
}

func TestEncodeIntLSBF(t *testing.T) {
	zeroEncoded := encodeIntLSBF(0)
	oneEncoded := encodeIntLSBF(1)
	if !bytes.Equal(zeroEncoded, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("Zero LSBF encoding failed")
	}
	if !bytes.Equal(oneEncoded, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("One LSBF encoding failed")
	}
}

func TestEncodeIntMSBF(t *testing.T) {
	zeroEncoded := encodeIntMSBF(0)
	oneEncoded := encodeIntMSBF(1)
	if !bytes.Equal(zeroEncoded, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("Zero MSBF encoding failed")
	}
	if !bytes.Equal(oneEncoded, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) {
		t.Fatalf("One MSBF encoding failed")
	}
}

func TestPadData(t *testing.T) {
	zeroes := make([]byte, 32)
	longer := make([]byte, 33)
	paddedLonger := make([]byte, 64)

	// Test padding an empty bufer
	zeroPad := padData([]byte{}, 32)
	if !bytes.Equal(zeroes, zeroPad) {
		t.Fatalf("Padded empty value is not correct!")
	}

	longerPad := padData(longer, 32)
	if !bytes.Equal(longerPad, paddedLonger) {
		t.Fatalf("Length extenion is incorrect!")
	}
}
