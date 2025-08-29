package hash

import (
	"elementhash/elementfunc"
	"hash"
)

const (
	ELT_FUNC_HASH uint64 = 2
)

type ElementHash struct {
	eFunc elementfunc.ElementFunc
}

func New(h func() hash.Hash) ElementHash {
	return NewWithSeparator(h, []byte(nil))
}

func NewWithSeparator(h func() hash.Hash, sep []byte) ElementHash {
	eFunc := elementfunc.New(h, ELT_FUNC_HASH, []byte(nil), sep)
	return ElementHash{eFunc: eFunc}
}

func (h *ElementHash) Write(data []byte) {
	h.eFunc.Write(data)
}

func (h *ElementHash) Sum(b []byte) []byte {
	return h.eFunc.Sum(b)
}

func (h *ElementHash) Size() int      { return h.eFunc.Size() }
func (m *ElementHash) BlockSize() int { return m.eFunc.BlockSize() }
func (m *ElementHash) Reset()         { m.eFunc.Reset() }
