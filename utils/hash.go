package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
)

const HashSize = 32

type Hash [HashSize]uints.U8

func (h Hash) ToValue(api frontend.API, field *emulated.Field[emparams.BLS12381Fp]) *emulated.Element[emparams.BLS12381Fp] {
	hashBits := make([]frontend.Variable, 256)
	for i := 0; i < HashSize; i++ {
		vBits := api.ToBinary(h[i].Val, 8)
		copy(hashBits[i*8:(i+1)*8], vBits)
	}

	rst := field.FromBits(hashBits...)
	return rst
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
