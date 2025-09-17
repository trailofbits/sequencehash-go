package mac

// This package is a thin wrapper around the ElementFunc struct; see the
// ElementFunc package for more details.

import (
	elementfunc "elementhash/internal"
	"hash"
)

const (
	ELT_FUNC_MAC uint64 = 1
)

type ElementMAC struct {
	eFunc elementfunc.ElementFunc
}

func NewWithSeparator(h func() hash.Hash, key []byte, sep []byte) ElementMAC {
	eFunc := elementfunc.New(
		h,
		ELT_FUNC_MAC,
		key,
		sep)
	return ElementMAC{eFunc: eFunc}
}

func New(h func() hash.Hash, key []byte) ElementMAC {
	return NewWithSeparator(h, key, []byte(nil))
}

func (m *ElementMAC) Write(data []byte)   { m.eFunc.Write(data) }
func (m *ElementMAC) Sum(b []byte) []byte { return m.eFunc.Sum(b) }
func (m *ElementMAC) Size() int           { return m.eFunc.Size() }
func (m *ElementMAC) BlockSize() int      { return m.eFunc.BlockSize() }
func (m *ElementMAC) Reset()              { m.eFunc.Reset() }
