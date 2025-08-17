package mac

import (
	"encoding/binary"
	"hash"
)

const (
	ELT_HASH_I = "ELTHSH_I"
	ELT_HASH_O = "ELTHSH_O"
)

// The `ElementMAC` struct holds all the state informtion for MAC calculations.
// Note that `elementCount` is limited to 64 bits instead of the 128 bits in
// the specification. This is technically a limitation against the spec, but if
// you have a use case where this genuinely matters, I want to hang out at your
// workplace, because you're probably doing something really cool or really
// stupid, and both are fun to watch.
//
// Potential updates and enhancements:
//   - Remove the `key` and `sep` fields, which are only used for reset. Use
//     binary marshaling of `Hash` structs to create copies of the inner and
//     outer `Hash` structs.
//   - Keep `key` and `sep`, and extend the API so same MAC can be efficiently
//     computed with multiple separators.
type ElementMAC struct {
	innerHash    hash.Hash
	outerHash    hash.Hash
	hashFunc     func() hash.Hash
	key          []byte
	sep          []byte
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

// Creates a new `ElementMAC` instance with the given key and hash function,
// and no domain separator. To create an `ElementMAC` instance with a domain
// separator, use `NewWithSeparator`.
func New(h func() hash.Hash, key []byte) ElementMAC {
	return NewWithSeparator(h, key, []byte(nil))
}

func (m *ElementMAC) initializeMAC() {
	m.innerHash = m.hashFunc()
	m.outerHash = m.hashFunc()

	keyLen := encodeIntMSBF(uint64(len(m.key)))
	sepLen := encodeIntMSBF(uint64(len(m.sep)))
	derivedKey := deriveBlock(m.key, m.hashFunc)
	derivedSep := deriveBlock(m.sep, m.hashFunc)

	// Set up the inner hash
	innerBlock := append([]byte(ELT_HASH_I), keyLen...)
	innerBlock = padData(innerBlock, uint64(m.innerHash.BlockSize()))
	m.innerHash.Write(innerBlock)
	m.innerHash.Write(derivedKey)

	// Set up the outer hash
	outerBlock := append([]byte(ELT_HASH_O), sepLen...)
	outerBlock = append(outerBlock, keyLen...)
	outerBlock = padData(outerBlock, uint64(m.outerHash.BlockSize()))
	m.outerHash.Write(outerBlock)
	m.outerHash.Write(derivedSep)
	m.outerHash.Write(derivedKey)

	// Reset our input count
	m.elementCount = 0
}

func NewWithSeparator(
	h func() hash.Hash,
	k []byte,
	s []byte) ElementMAC {
	keyCopy := make([]byte, len(k))
	sepCopy := make([]byte, len(s))
	copy(keyCopy, k)
	copy(sepCopy, s)

	newMac := ElementMAC{
		innerHash:    nil,
		outerHash:    nil,
		hashFunc:     h,
		key:          keyCopy,
		sep:          sepCopy,
		elementCount: 0,
		finished:     false,
	}
	newMac.initializeMAC()

	return newMac
}

func (m *ElementMAC) Write(data []byte) {
	if m.finished {
		panic("Cannot write to ElementMAC that has alreay been computed")
	}
	// Write the 16-byte length of the data first
	length := uint64(len(data))
	m.innerHash.Write(encodeIntLSBF(length))

	// Write the input
	m.innerHash.Write(data)
	m.elementCount += 1
}

func (m *ElementMAC) Size() int      { return m.outerHash.Size() }
func (m *ElementMAC) BlockSize() int { return m.innerHash.BlockSize() }

func (m *ElementMAC) Sum(b []byte) []byte {
	if !m.finished {
		countBytes := encodeIntMSBF(m.elementCount)
		outBytes := encodeIntMSBF(uint64(m.outerHash.Size()))
		//m.innerHash.Write(countBytes)

		innerResult := m.innerHash.Sum([]byte(nil))
		m.outerHash.Write(countBytes)
		m.outerHash.Write(outBytes)
		m.outerHash.Write(innerResult)
		m.finished = true
	}
	outerResult := m.outerHash.Sum([]byte(nil))
	return outerResult
}

func (m *ElementMAC) Reset() {
	m.initializeMAC()
}
