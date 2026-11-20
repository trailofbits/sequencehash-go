package mac

// This package is a thin wrapper around the SequenceFunc struct; see the
// SequenceFunc package for more details.

import (
	"fmt"
	"hash"
	sequencefunc "sequencehash-go/internal"
)

const (
	SEQ_FUNC_MAC uint64 = 1
	MIN_KEY_LEN  uint64 = 32
	MIN_HASH_LEN int    = 32
)

type SequenceMAC struct {
	eFunc sequencefunc.SequenceFunc
}

// Creates a new SequenceMAC instance given a hash function and key. Fails if
// the key is shorter than 32 bytes, or if the hash function's output is
// shorter than 32 bytes.
//
// The SequenceHash specification states that keys must be at least 32 bytes.
// It also says that implementations SHOULD emit warnings when SequenceMAC is
// used with a short hash (output under 32 bytes), because MAC security is then
// bounded by the output length regardless of key length, and that
// implementations MAY reject short hashes as long as the rejection is
// documented. Go has no idiomatic way for a library to emit a warning, so New
// rejects short hashes instead. That excludes SHA-1, MD5, SHA-224 and
// SHA3-224, among others. Use NewWithShortHash to opt in to a short hash.
func New(h func() hash.Hash, key []byte) (*SequenceMAC, error) {
	if h().Size() < MIN_HASH_LEN {
		return nil, fmt.Errorf("Hash output is too short; see NewWithShortHash")
	}
	return NewWithShortHash(h, key)
}

// Creates a new SequenceMAC instance like New, but also accepts a short hash
// (output under 32 bytes). Fails if the key is shorter than 32 bytes.
//
// With a short hash, MAC security is bounded by the hash's output length
// regardless of key length. Calling this function instead of New is the
// explicit acknowledgement of that risk that the specification's warning is
// meant to produce. Prefer New with a hash that has at least 32 bytes of
// output, such as SHA-256.
func NewWithShortHash(h func() hash.Hash, key []byte) (*SequenceMAC, error) {
	if uint64(len(key)) < MIN_KEY_LEN {
		return nil, fmt.Errorf("Provided key is too short")
	}

	result := new(SequenceMAC)

	eFunc := sequencefunc.New(
		h,
		SEQ_FUNC_MAC,
		key)
	result.eFunc = eFunc
	return result, nil
}

func (m *SequenceMAC) Add(data []byte) { m.eFunc.Add(data) }
func (m *SequenceMAC) Result() []byte  { return m.eFunc.Result() }
func (m *SequenceMAC) ResultWithCustomizer(cust []byte) []byte {
	return m.eFunc.ResultWithCustomizer(cust)
}
func (m *SequenceMAC) OutputSize() int { return m.eFunc.Size() }
func (m *SequenceMAC) BlockSize() int  { return m.eFunc.BlockSize() }
