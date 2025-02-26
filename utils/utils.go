package utils

import (
	"github.com/consensys/gnark/frontend"
)

// IsEqual returns 1 if a == b, 0 otherwise
func IsEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

func AreVarsEquals(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	n := len(a)
	if len(b) != n {
		panic("len(a) != len(b)")
	}

	sum := frontend.Variable(1)
	for i := 0; i < n; i++ {
		t := IsEqual(api, a[i], b[i])
		sum = api.And(sum, t)
	}

	return sum
}

func ValsFromBytes(data []byte, bitsPerVar int) []frontend.Variable {
	bytesPerVar := (bitsPerVar + 7) / 8
	ret := make([]frontend.Variable, 0)

	for i := 0; i < len(data); i += bytesPerVar {
		ret = append(ret, data[i:i+bytesPerVar])
	}

	return ret
}
