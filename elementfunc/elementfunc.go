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
	outerHash    hash.Hash
	hashFunc     func() hash.Hash
	key          []byte
	sep          []byte
	funcID       uint64
	elementCount uint64
	finished     bool
}

// Encodes a 64-bit integer into a 16-byte array, most-significant byte first.
// Note that, in the `ElementMAC` specification, inputs are allowed to be as
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
func deriveBlock(data []byte, h func() hash.Hash) []byte {
	blockSize := h().BlockSize()

	// Hash our value down if it's too large
	var reduced []byte
	if len(data) > blockSize {
		reducer := h()
		reducer.Write(data)
		reduced = reducer.Sum([]byte(nil))
	} else {
		reduced = data
	}

	// Pad out our reduced key
	padded := padData(reduced, uint64(blockSize))

	// Zero pad and return the block
	return padded
}

func genInnerHeader(h func() hash.Hash, keyLen uint64, funcID uint64) []byte {
	keyLenBytes := encodeIntMSBF(keyLen)
	funcBytes := encodeIntMSBF(funcID)
	header := append([]byte(ELT_HASH_I), funcBytes...)
	header = append(header, keyLenBytes...)
	header = padData(header, uint64(h().BlockSize()))
	return header
}

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

func (f *ElementFunc) initialize() {
	lenKey := uint64(len(f.key))
	lenSep := uint64(len(f.sep))

	// Derive our key and separator blocks
	keyBlock := deriveBlock(f.key, f.hashFunc)
	sepBlock := deriveBlock(f.sep, f.hashFunc)

	// Start with fresh hashes
	f.innerHash = f.hashFunc()
	f.outerHash = f.hashFunc()

	// Initialize the inner hash
	innerHeader := genInnerHeader(f.hashFunc, lenKey, f.funcID)
	f.innerHash.Write(innerHeader)
	f.innerHash.Write(keyBlock)

	// Initializer the outer hash
	outerHeader := genOuterHeader(f.hashFunc, lenKey, lenSep, f.funcID)
	f.outerHash.Write(outerHeader)
	f.outerHash.Write(sepBlock)
	f.outerHash.Write(keyBlock)
}

func (f *ElementFunc) finalize() {
	if !f.finished {
		countBytes := encodeIntMSBF(uint64(f.elementCount))
		outBytes := encodeIntMSBF(uint64(f.hashFunc().Size()))
		innerHash := f.innerHash.Sum([]byte(nil))

		f.outerHash.Write(countBytes)
		f.outerHash.Write(outBytes)
		f.outerHash.Write(innerHash)

		f.finished = true
	}
}

func (f *ElementFunc) Sum(b []byte) []byte {
	f.finalize()
	return f.outerHash.Sum(b)
}

func (f *ElementFunc) Write(data []byte) {
	if f.finished {
		panic("Cannot write to ElementFunc that has alreay been computed")
	}
	lenBytes := encodeIntLSBF(uint64(len(data)))
	f.innerHash.Write(lenBytes)
	f.innerHash.Write(data)
	f.elementCount += 1
}

func (f *ElementFunc) Size() int {
	return f.outerHash.Size()
}

func (f *ElementFunc) BlockSize() int {
	return f.innerHash.BlockSize()
}

func (f *ElementFunc) Reset() {
	f.initialize()
}

func New(h func() hash.Hash, eFunc uint64, key []byte, sep []byte) ElementFunc {
	keyCopy := make([]byte, len(key))
	sepCopy := make([]byte, len(sep))
	copy(keyCopy, key)
	copy(sepCopy, sep)
	elementFunc := ElementFunc{
		innerHash:    nil,
		outerHash:    nil,
		hashFunc:     h,
		key:          keyCopy,
		sep:          sepCopy,
		funcID:       eFunc,
		elementCount: 0,
		finished:     false,
	}
	elementFunc.initialize()
	return elementFunc
}
