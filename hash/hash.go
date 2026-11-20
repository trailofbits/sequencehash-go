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

// Creates a new SequenceHash instance given a hash function.
//
// Any hash function is accepted, including short hashes (output under 32
// bytes, such as SHA-1, MD5 or SHA-224). The SequenceHash specification allows
// short hashes for SequenceHash but says that implementations that allow them
// SHOULD document the risks: SequenceHash is only as secure as the underlying
// hash, and a short output gives less than 128-bit collision resistance.
// Prefer a hash with at least 32 bytes of output, such as SHA-256.
func New(h func() hash.Hash) (*SequenceHash, error) {
	result := new(SequenceHash)

	eFunc := sequencefunc.New(
		h,
		SEQ_FUNC_HASH,
		nil)
	result.eFunc = eFunc
	return result, nil
}

func (m *SequenceHash) Add(data []byte) { m.eFunc.Add(data) }
func (m *SequenceHash) Result() []byte  { return m.eFunc.Result() }
func (m *SequenceHash) ResultWithCustomizer(cust []byte) []byte {
	return m.eFunc.ResultWithCustomizer(cust)
}
func (m *SequenceHash) OutputSize() int { return m.eFunc.Size() }
func (m *SequenceHash) BlockSize() int  { return m.eFunc.BlockSize() }
