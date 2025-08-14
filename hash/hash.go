package hash

import (
	"elementhash/mac"
	"hash"
)

type ElementHash struct {
	mac mac.ElementMAC
}

func New(h func() hash.Hash) ElementHash {
	mac := mac.New(h, []byte(nil))
	return ElementHash{mac: mac}
}

func NewWithSeparator(h func() hash.Hash, sep []byte) ElementHash {
	mac := mac.NewWithSeparator(h, []byte(nil), sep)
	return ElementHash{mac: mac}
}

func (h *ElementHash) Write(data []byte) {
	h.mac.Write(data)
}

func (h *ElementHash) Sum(b []byte) []byte {
	return h.Sum(b)
}

func (h *ElementHash) Reset() {
	h.mac.Reset()
}
