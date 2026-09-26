package mac

// This package is a thin wrapper around the SequenceFunc struct; see the
// SequenceFunc package for more details.

import (
	sequencefunc "sequencehash/internal"
	"hash"
	"fmt"
)

const (
	SEQ_FUNC_MAC uint64 = 1
	MIN_KEY_LEN uint64 = 32
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

func (m *SequenceMAC) Add(data []byte)  { m.eFunc.Add(data) }
func (m *SequenceMAC) Result() []byte	{ return m.eFunc.Sum() }
func (m *SequenceMAC) ResultWithCustomizer(cust []byte) []byte	{ return m.eFunc.ResultWithCustomizer(cust) }
func (m *SequenceMAC) OutputSize() int  { return m.eFunc.Size() }
func (m *SequenceMAC) BlockSize() int   { return m.eFunc.BlockSize() }
