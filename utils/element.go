package utils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

// assuming e has been reduced
func RetrieveU8ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	return retrieveSmallValueFromElement[FR](api, e, 8)
}

// assuming e has been reduced
func RetrieveU32ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	return retrieveSmallValueFromElement[FR](api, e, 32)
}

func retrieveSmallValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR], nbBits int) frontend.Variable {
	var fr FR
	if fr.BitsPerLimb() != 64 {
		panic("unsupported number format")
	}

	nbLimbs := fr.NbLimbs()
	for i := 1; i < int(nbLimbs); i++ {
		api.AssertIsEqual(e.Limbs[i], 0)
	}

	r := e.Limbs[0]

	rcheck := rangecheck.New(api)
	rcheck.Check(r, nbBits)
	return r
}

func RetrieveU254ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	rs := RetrieveVarsFromElements(api, []emulated.Element[FR]{e})
	r := rs[0]

	var fr FR
	if fr.Modulus().BitLen() > 254 {
		rcheck := rangecheck.New(api)
		rcheck.Check(r, 254)
	}

	return r
}

func RetrieveVarsFromElements[FR emulated.FieldParams](
	api frontend.API, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) []frontend.Variable {
	var fr FR
	bitsPerLimb := int(fr.BitsPerLimb())

	var maxBits int
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = fr.Modulus().BitLen()
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	n := len(witnessValues)
	for i := 0; i < n; i++ {
		nbLimbs := len(witnessValues[i].Limbs)
		for j := nbEffectiveLimbs; j < nbLimbs; j++ {
			api.AssertIsEqual(witnessValues[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	rst := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		eleLimbs := witnessValues[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		rst[i] = composed
	}

	return rst
}

func AssertValsVSWtnsElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	n := len(witnessValues)
	if len(vars) != n {
		panic("len(vars) != len(witnessValues)")
	}

	vals := RetrieveVarsFromElements(api, witnessValues, nbMaxBitsPerVar...)
	for i := 0; i < n; i++ {
		api.AssertIsEqual(vals[i], vars[i])
	}
}

func TestValsVSWtnsElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	n := len(witnessValues)
	if len(vars) != n {
		panic("len(vars) != len(witnessValues)")
	}

	vals := RetrieveVarsFromElements(api, witnessValues, nbMaxBitsPerVar...)

	sum := frontend.Variable(1)
	for i := 0; i < n; i++ {
		t := IsEqual(api, vars[i], vals[i])
		sum = api.And(sum, t)
	}

	return sum
}
