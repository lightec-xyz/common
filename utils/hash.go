package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const HashSize = 32

type Hash [HashSize]uints.U8

func FromBytesHash(hash [HashSize]byte) Hash {
	return Hash(uints.NewU8Array(hash[:]))
}

func (h Hash) IsEqual(api frontend.API, other Hash) frontend.Variable {
	sum := frontend.Variable(1)
	for i := 0; i < HashSize; i++ {
		va, vb := h[i].Val, other[i].Val
		d := api.Sub(va, vb)
		test := api.IsZero(d)
		sum = api.And(sum, test)
	}

	return sum
}

func (h Hash) AssertIsEqual(api frontend.API, other Hash) {
	for i := 0; i < HashSize; i++ {
		api.AssertIsEqual(h[i].Val, other[i].Val)
	}
}
