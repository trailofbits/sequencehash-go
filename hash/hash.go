package hash

import (
	sequencefunc "sequencehash/internal"
	"hash"
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

func (m *SequenceHash) Add(data []byte)  { m.eFunc.Add(data) }
func (m *SequenceHash) Result() []byte	{ return m.eFunc.Sum() }
func (m *SequenceHash) ResultWithCustomizer(cust []byte) []byte	{ return m.eFunc.SumWithCustomizer(cust) }
func (m *SequenceHash) OutputSize() int  { return m.eFunc.Size() }
func (m *SequenceHash) BlockSize() int   { return m.eFunc.BlockSize() }
