package sequencefunc

import (
	"encoding/binary"
	"hash"
	"crypto/subtle"
)

const (
	SEQ_HASH_I              = "SEQHSH_I"
	SEQ_HASH_O              = "SEQHSH_O"
	FUNCTION_ID_MAC  uint64 = 1
	FUNCTION_ID_HASH uint64 = 2
	TWEAK_INNER byte = 0x55
	TWEAK_OUTER byte = 0xaa
)

type SequenceFunc struct {
	innerHash    hash.Hash
	outerHash    hash.Hash
	hashFunc     func() hash.Hash
	lenKey       uint64	// Needed for generating the headers
	funcID       uint64
	SequenceCount uint64
	finished bool
}

// Encodes a 64-bit integer into a 16-byte array, most-significant byte first.
// Note that, in the `SequenceHash` specification, inputs are allowed to be as
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
//
// Note that, if `blockSize` is 1, this is a no-op. If `blockSize` is 0, it is
// updated to 1, rendering this a no-op. If you're using a hash with a 0- or
// 1-byte block, you probably have larger problems than SequenceHash can solve.
func padData(data []byte, blockSize uint64) []byte {
	if blockSize < 1 {
		blockSize = 1
	}
	dataLength := uint64(len(data))
	blockCount := (dataLength + blockSize - 1) / blockSize
	if blockCount < 1 {
		blockCount = 1
	}

	totalLength := blockCount * blockSize
	padLength := totalLength - dataLength
	padding := make([]byte, padLength)
	return append(data, padding...)
}

func deriveBlock(data []byte, h func() hash.Hash, tweak byte) []byte {
	reducer := h()

	// Hash our value down if it's too large
	var reduced []byte
	if len(data) > reducer.BlockSize() {
		reducer.Write(data)
		reduced = reducer.Sum([]byte(nil))
	} else {
		reduced = data
	}

	// Pad out our key
	padded := padData(reduced, uint64(reducer.BlockSize()))

	// Apply the tweak
	padded[0] ^= tweak

	// Zero pad and return the block
	return padded
}

// Generates the inner header for the hash, according to the specication:
//
//	PAD(
//	   "SEQHSH_I" ||
//	    EncodeMSBF(funcID) ||
//	    EncodeMSBF(keyLen) ||
//	)
func genInnerHeader(h func() hash.Hash, keyLen uint64, funcID uint64) []byte {
	keyLenBytes := encodeIntMSBF(keyLen)
	funcBytes := encodeIntMSBF(funcID)
	header := append([]byte(SEQ_HASH_I), funcBytes...)
	header = append(header, keyLenBytes...)
	header = padData(header, uint64(h().BlockSize()))
	return header
}

// Generates the outer header for the hash, according to the specication:
//
//	PAD(
//	   "SEQHSH_O" ||
//	   EncodeMSBF(funcID) ||
//	   EncodeMSBF(sepLen) ||
//	   EncodeMSBF(keyLen) ||
//	)
func genOuterHeader(h func() hash.Hash, keyLen uint64, sepLen uint64,
	funcID uint64) []byte {
	keyLenBytes := encodeIntMSBF(keyLen)
	sepLenBytes := encodeIntMSBF(sepLen)
	funcBytes := encodeIntMSBF(funcID)
	header := append([]byte(SEQ_HASH_O), funcBytes...)
	header = append(header, sepLenBytes...)
	header = append(header, keyLenBytes...)
	header = padData(header, uint64(h().BlockSize()))
	return header
}

func (f *SequenceFunc) ResultWithCustomizer(customizer []byte) []byte {
	if f.finished {
		panic("Cannot compute result twice")
	}
	// Tag the SequenceFunc object as non-updatable
	f.finished = true

	// Compute the inner hash
	innerHash := f.innerHash.Sum(nil)

	// Compute the outer hash
	outerHeader := genOuterHeader(f.hashFunc, f.lenKey, uint64(len(customizer)), f.funcID)
	derivedCustomizer := deriveBlock(customizer, f.hashFunc, 0x00)
	f.outerHash.Write(outerHeader)
	f.outerHash.Write(derivedCustomizer)
	f.outerHash.Write(encodeIntMSBF(f.SequenceCount))
	f.outerHash.Write(encodeIntMSBF(uint64(f.innerHash.Size())))
	f.outerHash.Write(innerHash)

	return f.outerHash.Sum(nil)
}

func (f *SequenceFunc) Sum() []byte {
	return f.ResultWithCustomizer(nil)
}

func (f *SequenceFunc) Add(data []byte) {
	// Because this implementation limits itself to 2^64-1 inputs instead of
	// the 2^128-1 inputs from the spec, we want to flag when we get past our
	// max and indicate that the max is due to the implementation, not the
	// standard
	if f.SequenceCount == 0xffff_ffff_ffff_ffff { // coverage-ignore
		panic("Maximum implementation-supported Sequence count exceeded")
	}

	lenBytes := encodeIntLSBF(uint64(len(data)))
	f.innerHash.Write(data)
	f.innerHash.Write(lenBytes)
	f.SequenceCount += 1
}

func (f *SequenceFunc) Size() int {
	return f.innerHash.Size()
}

func (f *SequenceFunc) BlockSize() int {
	return f.innerHash.BlockSize()
}

// Creates a new SequenceFunc instance and initializes it
func New(h func() hash.Hash, eFunc uint64, key []byte) SequenceFunc {
	SequenceFunc := SequenceFunc{
		innerHash:     nil,
		outerHash:     nil,
		hashFunc:      h,
		lenKey:        uint64(len(key)),
		funcID:        eFunc,
		SequenceCount: 0,
		finished: false,
	}
	SequenceFunc.initialize(key)
	return SequenceFunc
}

func (f *SequenceFunc) initialize(key []byte) {
	// Derive our key and separator blocks
	derived_key_inner := deriveBlock(key, f.hashFunc, TWEAK_INNER)
	derived_key_outer := deriveBlock(key, f.hashFunc, TWEAK_OUTER)

	// Initialize the inner hash
	innerHeader := genInnerHeader(f.hashFunc, f.lenKey, f.funcID)
	f.innerHash = f.hashFunc()
	f.innerHash.Write(derived_key_inner)
	f.innerHash.Write(innerHeader)

	// Initialize the outer hash
	f.outerHash = f.hashFunc()
	f.outerHash.Write(derived_key_outer)

	// Nix our copies of the derived keys
	subtle.XORBytes(derived_key_inner, derived_key_inner, derived_key_inner)
	subtle.XORBytes(derived_key_outer, derived_key_outer, derived_key_outer)
}
