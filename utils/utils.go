package utils

import "github.com/consensys/gnark/frontend"

// LessThan returns 1 if a < b, 0 otherwise
func LessThan(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Add(api.Cmp(a, b), 1))
}

// IsEqual returns 1 if a == b, 0 otherwise
func IsEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}
