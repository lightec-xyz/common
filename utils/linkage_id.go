package utils

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type LinkageID struct {
	Vals       []frontend.Variable
	BitsPerVar int
}
type LinkageIDBytes []byte

func NewLinkageID(v []frontend.Variable, b int) LinkageID {
	return LinkageID{
		Vals:       v,
		BitsPerVar: b,
	}
}
func PlaceholderLinkageID(nbEles, bitsPerVar int) LinkageID {
	return LinkageID{
		Vals:       make([]frontend.Variable, nbEles),
		BitsPerVar: bitsPerVar,
	}
}
func (id LinkageID) AssertIsEqual(api frontend.API, other LinkageID) {
	api.AssertIsEqual(id.BitsPerVar, other.BitsPerVar)
	api.AssertIsEqual(len(id.Vals), len(other.Vals))
	for i := 0; i < len(id.Vals); i++ {
		api.AssertIsEqual(id.Vals[i], other.Vals[i])
	}
}
func (id LinkageID) IsEqual(api frontend.API, other LinkageID) frontend.Variable {
	api.AssertIsEqual(id.BitsPerVar, other.BitsPerVar)
	return areVarsEquals(api, id.Vals, other.Vals)
}
func (id LinkageID) ToBytes(api frontend.API) ([]uints.U8, error) {
	vals := make([]frontend.Variable, len(id.Vals))
	copy(vals, id.Vals)
	slices.Reverse[[]frontend.Variable](vals)

	return ValsToU8s(api, vals, id.BitsPerVar)
}

// little-endian here
func LinkageIDFromU8s(api frontend.API, data []uints.U8, bitsPerVar int) LinkageID {
	bits := make([]frontend.Variable, len(data)*8)
	for i := 0; i < len(data); i++ {
		bs := api.ToBinary(data[i].Val, 8)
		copy(bits[i*8:(i+1)*8], bs)
	}

	vals := bitsToVars(api, bits, bitsPerVar)

	return LinkageID{
		Vals:       vals,
		BitsPerVar: bitsPerVar,
	}
}
func LinkageIDFromBytes(data LinkageIDBytes, bitsPerVar int) LinkageID {
	return LinkageID{
		Vals:       ValsFromBytes(data, bitsPerVar),
		BitsPerVar: bitsPerVar,
	}
}

func AssertIDWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, els []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	AssertValsWithWitnessElements[FR](api, id.Vals, els, nbMaxBitsPerVar...)
}

func AssertFpWitness[FR emulated.FieldParams](
	api frontend.API, fp FingerPrint, els []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	AssertValsWithWitnessElements[FR](api, fp.Vals, els, nbMaxBitsPerVar...)
}

func AssertValsWithWitnessElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, els []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	api.AssertIsEqual(len(els), len(vars))

	var fr FR
	var maxBits int

	bitsPerLimb := int(FR.BitsPerLimb(fr))
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = int(fr.NbLimbs() * fr.BitsPerLimb())
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	for i := 0; i < len(els); i++ {
		for j := nbEffectiveLimbs; j < int(fr.NbLimbs()); j++ {
			api.AssertIsEqual(els[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	for i := 0; i < len(vars); i++ {
		eleLimbs := els[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		api.AssertIsEqual(vars[i], composed)
	}
}

func IsIDEqualToWitness[FR emulated.FieldParams](
	api frontend.API, id LinkageID, els []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	return TestValsWithWitnessElements[FR](api, id.Vals, els, nbMaxBitsPerVar...)
}

func TestValsWithWitnessElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, els []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	api.AssertIsEqual(len(els), len(vars))

	var fr FR
	var maxBits int

	bitsPerLimb := int(FR.BitsPerLimb(fr))
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = int(fr.NbLimbs() * fr.BitsPerLimb())
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	for i := 0; i < len(els); i++ {
		for j := nbEffectiveLimbs; j < int(fr.NbLimbs()); j++ {
			api.AssertIsEqual(els[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	sum := frontend.Variable(1)
	for i := 0; i < len(vars); i++ {
		eleLimbs := els[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		diff := api.Sub(vars[i], composed)
		t := api.IsZero(diff)
		sum = api.And(sum, t)
	}

	return sum
}
