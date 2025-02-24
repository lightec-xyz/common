package utils

import (
	"math"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
)

/**
 * a, b should be already strictly reduced, so that we can employ nbSkipLimbs
 **/
func ElementsLessEq[T emulated.FieldParams](api frontend.API, a, b emulated.Element[T], nbSkipLimbs ...int) frontend.Variable {
	var t T
	if t.BitsPerLimb() != 64 {
		panic("unsupported number format")
	}

	maxU64 := big.NewInt(0).SetUint64(math.MaxUint64)
	cmp := cmp.NewBoundedComparator(api, maxU64, false)

	skip := 0
	if len(nbSkipLimbs) > 0 {
		skip = nbSkipLimbs[0]
	}

	topLimb := int(t.NbLimbs()) - 1 - skip
	isSofarEq := IsEqual(api, a.Limbs[topLimb], b.Limbs[topLimb])
	isSofarLess := cmp.IsLess(a.Limbs[topLimb], b.Limbs[topLimb])

	for i := topLimb - 1; i >= 0; i-- {
		va, vb := a.Limbs[i], b.Limbs[i]

		isThisEq := IsEqual(api, va, vb)
		isThisLess := cmp.IsLess(va, vb)

		isSofarLess = api.Select(isSofarEq, isThisLess, isSofarLess)
		isSofarEq = api.And(isSofarEq, isThisEq)
	}

	for i := t.NbLimbs() - 1; i > uint(topLimb); i-- {
		api.AssertIsEqual(a.Limbs[i], 0)
		api.AssertIsEqual(b.Limbs[i], 0)
	}

	return api.Or(isSofarEq, isSofarLess)
}
