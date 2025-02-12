package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// LessThan returns 1 if a < b, 0 otherwise
func LessThan(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return cmp.IsLess(api, a, b)
}

// IsEqual returns 1 if a == b, 0 otherwise
func IsEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}
