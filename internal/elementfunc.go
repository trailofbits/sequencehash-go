package elementfunc

import (
	"encoding/binary"
	"hash"
)

const (
	ELT_HASH_I              = "ELTHSH_I"
	ELT_HASH_O              = "ELTHSH_O"
	FUNCTION_ID_MAC  uint64 = 1
	FUNCTION_ID_HASH uint64 = 2
)

type ElementFunc struct {
	innerHash    hash.Hash
	hashFunc     func() hash.Hash
	lenKey       uint64
	lenSep       uint64
	derivedKey   []byte // Needed to allow `Reset()`
	derivedSep   []byte // Needed to allow `Reset()`
	funcID       uint64
	elementCount uint64
}

// Encodes a 64-bit integer into a 16-byte array, most-significant byte first.
// Note that, in the `ElementHash` specification, inputs are allowed to be as
// long as 2^128 - 1 bytes. However, Go doesn't have built-in support for 128-
// bit integers, so this implementation cheats by assuming all inputs are no
// longer than 2^64-1 bytes, and padding with zeroes.
func encodeIntLSBF(n uint64) []byte {
	encoded := binary.LittleEndian.AppendUint64([]byte(nil), n)
	encoded = binary.LittleEndian.AppendUint64(encoded, 0)
	return encoded
}

// Encodes a 64-bit integer into a 16-byte array, least-significant byte first.
// See comments for `encodeIntLSBF` for discussions of standards compliance.
func encodeIntMSBF(n uint64) []byte {
	encoded := binary.BigEndian.AppendUint64([]byte(nil), 0)
	encoded = binary.BigEndian.AppendUint64(encoded, n)
	return encoded
}

// Zero-pads the given data out to the next multiple of `blockSize`. If the
// length of `data` is already a multiple of `blockSize`, no padding is
// performed, except when `len(data) == 0`, in which case a string of
// `blockSize` zeroes will be returned.
func padData(data []byte, blockSize uint64) []byte {
	dataLength := uint64(len(data))
	blockCount := (dataLength + blockSize - 1) / blockSize
	if blockCount == 0 {
		blockCount = 1
	}

	totalLength := blockCount * blockSize
	padLength := totalLength - dataLength
	padding := make([]byte, padLength)
	return append(data, padding...)
}

// Derives a key or separator block for `ElementMAC` by either padding `data`
// to the length of the underlying hash block (if it is shorter), returning
// `data` unchanged (if it is exactly the same length as the underlying hash
// block), or hashing `data` and padding out the result to the length of the
// underlying hash block.
//
//	If len(data) <= BlockSize
//		return PAD(data)
//	Else
//		return PAD(hash(data))
func deriveBlock(data []byte, h func() hash.Hash) []byte {
	reducer := h()

	// Hash our value down if it's too large
	var reduced []byte
	if len(data) > reducer.BlockSize() {
		reducer.Write(data)
		reduced = reducer.Sum([]byte(nil))
	} else {
		reduced = data
	}

	// Pad out our reduced key
	padded := padData(reduced, uint64(reducer.BlockSize()))

	// Zero pad and return the block
	return padded
}

// Generates the inner header for the hash, according to the specication:
//
//	PAD(
//	   "ELTHSH_I" ||
//	    EncodeMSBF(funcID) ||
//	    EncodeMSBF(keyLen) ||
//	)
func genInnerHeader(h func() hash.Hash, keyLen uint64, funcID uint64) []byte {
	keyLenBytes := encodeIntMSBF(keyLen)
	funcBytes := encodeIntMSBF(funcID)
	header := append([]byte(ELT_HASH_I), funcBytes...)
	header = append(header, keyLenBytes...)
	header = padData(header, uint64(h().BlockSize()))
	return header
}

// Generates the outer header for the hash, according to the specication:
//
//	PAD(
//	   "ELTHSH_O" ||
//	   EncodeMSBF(funcID) ||
//	   EncodeMSBF(sepLen) ||
//	   EncodeMSBF(keyLen) ||
//	)
func genOuterHeader(h func() hash.Hash, keyLen uint64, sepLen uint64,
	funcID uint64) []byte {
	keyLenBytes := encodeIntMSBF(keyLen)
	sepLenBytes := encodeIntMSBF(sepLen)
	funcBytes := encodeIntMSBF(funcID)
	header := append([]byte(ELT_HASH_O), funcBytes...)
	header = append(header, sepLenBytes...)
	header = append(header, keyLenBytes...)
	header = padData(header, uint64(h().BlockSize()))
	return header
}

func (f *ElementFunc) Sum(b []byte) []byte {
	outerHash := f.hashFunc()

	outerHeader := genOuterHeader(f.hashFunc, f.lenKey, f.lenSep, f.funcID)
	outerHash.Write(outerHeader)
	outerHash.Write(f.derivedSep)
	outerHash.Write(f.derivedKey)

	countBytes := encodeIntMSBF(uint64(f.elementCount))
	outBytes := encodeIntMSBF(uint64(f.hashFunc().Size()))
	innerHash := f.innerHash.Sum([]byte(nil))

	outerHash.Write(countBytes)
	outerHash.Write(outBytes)
	outerHash.Write(innerHash)
	return outerHash.Sum(b)
}

func (f *ElementFunc) Write(data []byte) {
	// Because this implementation limits itself to 2^64-1 inputs instead of
	// the 2^128-1 inputs from the spec, we want to flag when we get past our
	// max and indicate that the max is due to the implementation, not the
	// standard
	if f.elementCount == 0xffff_ffff_ffff_ffff { // coverage-ignore
		panic("Maximum implementation-supported element count exceeded")
	}

	lenBytes := encodeIntLSBF(uint64(len(data)))
	f.innerHash.Write(lenBytes)
	f.innerHash.Write(data)
	f.elementCount += 1
}

func (f *ElementFunc) Size() int {
	return f.innerHash.Size()
}

func (f *ElementFunc) BlockSize() int {
	return f.innerHash.BlockSize()
}

// Resets the ElementFunc instance for reuse.
func (f *ElementFunc) Reset() {
	innerHeader := genInnerHeader(f.hashFunc, f.lenKey, f.funcID)
	f.innerHash = f.hashFunc()
	f.innerHash.Write(innerHeader)
	f.innerHash.Write(f.derivedKey)
	f.elementCount = 0
}

// Creates a new ElementFunc instance and initializes it
func New(h func() hash.Hash, eFunc uint64, key []byte, sep []byte) ElementFunc {
	elementFunc := ElementFunc{
		innerHash:    nil,
		hashFunc:     h,
		lenKey:       uint64(len(key)),
		lenSep:       uint64(len(sep)),
		derivedKey:   nil,
		derivedSep:   nil,
		funcID:       eFunc,
		elementCount: 0,
	}
	elementFunc.initialize(key, sep)
	return elementFunc
}

func (f *ElementFunc) initialize(key []byte, sep []byte) {
	// Derive our key and separator blocks
	f.derivedKey = deriveBlock(key, f.hashFunc)
	f.derivedSep = deriveBlock(sep, f.hashFunc)

	// Initialize the inner hash
	innerHeader := genInnerHeader(f.hashFunc, f.lenKey, f.funcID)
	f.innerHash = f.hashFunc()
	f.innerHash.Write(innerHeader)
	f.innerHash.Write(f.derivedKey)
}
