package hash

import (
	"hash"
	sequencefunc "sequencehash-go/internal"
)

const (
	SEQ_FUNC_HASH uint64 = 2
)

type SequenceHash struct {
	eFunc sequencefunc.SequenceFunc
}

func New(h func() hash.Hash) (*SequenceHash, error) {
	result := new(SequenceHash)

	eFunc := sequencefunc.New(
		h,
		SEQ_FUNC_HASH,
		nil)
	result.eFunc = eFunc
	return result, nil
}

// Add appends one element to the sequence. Each call is one element: adding
// "ab" and then "cd" gives a different result from adding "abcd".
//
// Add panics if it is called after Result or ResultWithCustomizer.
func (m *SequenceHash) Add(data []byte) { m.eFunc.Add(data) }

// Result returns the output with an empty customization string. It is
// ResultWithCustomizer(nil).
//
// A result can be computed only once per instance: calling Result or
// ResultWithCustomizer again, or calling Add afterwards, panics. To get
// outputs for several customization strings, use one instance per string.
func (m *SequenceHash) Result() []byte { return m.eFunc.Result() }

// ResultWithCustomizer returns the output for the given customization
// (domain separation) string. Like Result, it can be called only once per
// instance.
func (m *SequenceHash) ResultWithCustomizer(cust []byte) []byte {
	return m.eFunc.ResultWithCustomizer(cust)
}
func (m *SequenceHash) OutputSize() int { return m.eFunc.Size() }
func (m *SequenceHash) BlockSize() int  { return m.eFunc.BlockSize() }
