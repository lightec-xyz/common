package utils

import (
	"github.com/consensys/gnark/frontend"
)

// IsEqual returns 1 if a == b, 0 otherwise
func IsEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}
