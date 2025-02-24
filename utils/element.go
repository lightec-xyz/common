package utils

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/rangecheck"
)

func RetrieveU8ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	var fr FR
	nbLimbs := fr.NbLimbs()
	for i := 1; i < int(nbLimbs); i++ {
		api.AssertIsEqual(e.Limbs[i], 0)
	}

	r := e.Limbs[0]
	rcheck := rangecheck.New(api)
	rcheck.Check(r, 8)
	return r
}

func RetrieveU32ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	var fr FR
	nbLimbs := fr.NbLimbs()
	for i := 1; i < int(nbLimbs); i++ {
		api.AssertIsEqual(e.Limbs[i], 0)
	}

	r := e.Limbs[0]

	rcheck := rangecheck.New(api)
	rcheck.Check(r, 32)
	return r
}

func RetrieveU128ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	var fr FR
	nbLimbs := fr.NbLimbs()
	for i := 2; i < int(nbLimbs); i++ {
		api.AssertIsEqual(e.Limbs[i], 0)
	}

	r := e.Limbs[0]
	for i := 1; i < 2; i++ {
		base := new(big.Int).Lsh(big.NewInt(1), uint(i*64))
		r = api.MulAcc(r, base, e.Limbs[i])
	}

	rcheck := rangecheck.New(api)
	rcheck.Check(r, 128)
	return r
}

func RetrieveU128ValuesFromElements[FR emulated.FieldParams](api frontend.API, nIn int, e []emulated.Element[FR]) []frontend.Variable {
	rst := make([]frontend.Variable, nIn)
	for i := 0; i < nIn; i++ {
		rst[i] = RetrieveU128ValueFromElement(api, e[i])
	}
	return rst
}

func RetrieveU254ValueFromElement[FR emulated.FieldParams](api frontend.API, e emulated.Element[FR]) frontend.Variable {
	var fr FR
	nbLimbs := fr.NbLimbs()
	for i := 4; i < int(nbLimbs); i++ {
		api.AssertIsEqual(e.Limbs[i], 0)
	}

	r := e.Limbs[0]
	for i := 1; i < 4; i++ {
		base := new(big.Int).Lsh(big.NewInt(1), uint(i*64))
		r = api.MulAcc(r, base, e.Limbs[i])
	}

	if fr.Modulus().BitLen() > 254 {
		rcheck := rangecheck.New(api)
		rcheck.Check(r, 254)
	}

	return r
}

func AssertValsVSWtnsElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	api.AssertIsEqual(len(witnessValues), len(vars))

	var fr FR
	var maxBits int

	bitsPerLimb := int(FR.BitsPerLimb(fr))
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = fr.Modulus().BitLen()
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	for i := 0; i < len(witnessValues); i++ {
		for j := nbEffectiveLimbs; j < int(fr.NbLimbs()); j++ {
			api.AssertIsEqual(witnessValues[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	for i := 0; i < len(vars); i++ {
		eleLimbs := witnessValues[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		api.AssertIsEqual(vars[i], composed)
	}
}

func TestValsVSWtnsElements[FR emulated.FieldParams](
	api frontend.API, vars []frontend.Variable, witnessValues []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	api.AssertIsEqual(len(witnessValues), len(vars))

	var fr FR
	var maxBits int

	bitsPerLimb := int(FR.BitsPerLimb(fr))
	if len(nbMaxBitsPerVar) == 0 {
		maxBits = fr.Modulus().BitLen()
	} else {
		maxBits = int(nbMaxBitsPerVar[0])
	}

	nbEffectiveLimbs := int((maxBits + bitsPerLimb - 1) / bitsPerLimb)

	for i := 0; i < len(witnessValues); i++ {
		for j := nbEffectiveLimbs; j < int(fr.NbLimbs()); j++ {
			api.AssertIsEqual(witnessValues[i].Limbs[j], 0)
		}
	}

	constFactor := big.NewInt(1)
	for i := 0; i < int(bitsPerLimb); i++ {
		constFactor = constFactor.Mul(constFactor, big.NewInt(2))
	}

	sum := frontend.Variable(1)
	for i := 0; i < len(vars); i++ {
		eleLimbs := witnessValues[i].Limbs
		composed := eleLimbs[nbEffectiveLimbs-1]
		for j := nbEffectiveLimbs - 2; j >= 0; j-- {
			v := api.Mul(composed, constFactor)
			composed = api.Add(v, eleLimbs[j])
		}

		t := IsEqual(api, vars[i], composed)
		sum = api.And(sum, t)
	}

	return sum
}
