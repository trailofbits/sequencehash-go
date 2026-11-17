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
)

type SequenceMAC struct {
	eFunc sequencefunc.SequenceFunc
}

// Creates a new SequenceMAC instance given a hash function and key. Can fail
// if the key is too short. The SequenceHash specification states that keys
// must be at least 32 bytes, and that implementations are allowed to reject
// hash functions, as long as the rejection criteria are documented.
func New(h func() hash.Hash, key []byte) (*SequenceMAC, error) {
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

// Add appends one element to the sequence. Each call is one element: adding
// "ab" and then "cd" gives a different result from adding "abcd".
//
// Add panics if it is called after Result or ResultWithCustomizer.
func (m *SequenceMAC) Add(data []byte) { m.eFunc.Add(data) }

// Result returns the output with an empty customization string. It is
// ResultWithCustomizer(nil).
//
// A result can be computed only once per instance: calling Result or
// ResultWithCustomizer again, or calling Add afterwards, panics. To get
// outputs for several customization strings, use one instance per string.
func (m *SequenceMAC) Result() []byte { return m.eFunc.Result() }

// ResultWithCustomizer returns the output for the given customization
// (domain separation) string. Like Result, it can be called only once per
// instance.
func (m *SequenceMAC) ResultWithCustomizer(cust []byte) []byte {
	return m.eFunc.ResultWithCustomizer(cust)
}
func (m *SequenceMAC) OutputSize() int { return m.eFunc.Size() }
func (m *SequenceMAC) BlockSize() int  { return m.eFunc.BlockSize() }
