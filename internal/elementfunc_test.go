package elementfunc

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestBlockSize(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil), []byte(nil))
	if eFunc.BlockSize() != sha256.BlockSize {
		t.Fatalf("Block size mismatch for SHA256")
	}

	eFunc = New(sha512.New, 0, []byte(nil), []byte(nil))
	if eFunc.BlockSize() != sha512.BlockSize {
		t.Fatalf("Block size mismatch for SHA512")
	}
}

func TestSize(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil), []byte(nil))
	if eFunc.Size() != sha256.Size {
		t.Fatalf("Size mismatch for SHA256")
	}

	eFunc = New(sha512.New, 0, []byte(nil), []byte(nil))
	if eFunc.Size() != sha512.Size {
		t.Fatalf("Size mismatch for SHA512")
	}
}

func TestWrite(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil), []byte(nil))
	eFunc.Write([]byte(nil))

}

func TestSum(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil), []byte(nil))
	eFunc.Write([]byte(nil))
	sum := eFunc.Sum([]byte(nil))
	if bytes.Equal(sum, make([]byte, 32)) {
		t.Fatalf("Incorrect sum")
	}
}

func TestReset(t *testing.T) {
	eFunc := New(sha256.New, 0, []byte(nil), []byte(nil))
	eFunc.Write([]byte(nil))
	sumFirst := eFunc.Sum([]byte(nil))
	eFunc.Write([]byte(nil))
	sumSecond := eFunc.Sum([]byte(nil))
	eFunc.Reset()
	eFunc.Write([]byte(nil))
	sumThird := eFunc.Sum([]byte(nil))

	if !bytes.Equal(sumFirst, sumThird) {
		t.Fatalf("Reset failure")
	}
	if bytes.Equal(sumFirst, sumSecond) {
		t.Fatalf("Continuation failure")
	}
}

func TestDeriveBlock(t *testing.T) {
	shortInput := make([]byte, 8)
	longInput := make([]byte, 256)

	longHash := sha256.Sum256(longInput)

	expectedShort := make([]byte, sha256.New().BlockSize())
	expectedLong := padData(longHash[:], sha256.BlockSize)

	shortDerived := deriveBlock(shortInput, sha256.New)
	longDerived := deriveBlock(longInput, sha256.New)

	if !bytes.Equal(expectedLong, longDerived) {
		t.Fatalf("Long derivation failed")
	}
	if !bytes.Equal(expectedShort, shortDerived) {
		t.Fatalf("Short derivation failed")
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
