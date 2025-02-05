package utils

import (
	"math"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/uints"
)

func ValsToU8s(api frontend.API, vals []frontend.Variable, bitsPerVar int) ([]uints.U8, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	bytesPerVar := bitsPerVar / 8
	ret := make([]uints.U8, bytesPerVar*len(vals))
	for i := 0; i < len(vals); i++ {
		bytes := byteArrayValueOf(api, uapi, vals[i], bytesPerVar)
		begin := i * bytesPerVar
		end := begin + bytesPerVar
		copy(ret[begin:end], bytes)
	}

	return ret, nil
}

func ValsFromBytes(data []byte, bitsPerVar int) []frontend.Variable {
	bytesPerVar := (bitsPerVar + 7) / 8
	ret := make([]frontend.Variable, 0)
	for i := 0; i < len(data); i += bytesPerVar {
		tmp := make([]byte, bytesPerVar)
		copy(tmp, data[i:i+bytesPerVar])
		slices.Reverse[[]byte](tmp)
		ret = append(ret, tmp)
	}

	slices.Reverse[[]frontend.Variable](ret)
	return ret
}

func BitsToVars(api frontend.API, bits []frontend.Variable, bitsPerVar int) []frontend.Variable {

	vals := make([]frontend.Variable, 0)
	for i := 0; i < len(bits); i += bitsPerVar {
		val := api.FromBinary(bits[i : i+bitsPerVar]...)
		vals = append(vals, val)
	}

	slices.Reverse[[]frontend.Variable](vals)
	return vals
}

func AreVarsEquals(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	api.AssertIsEqual(len(a), len(b))
	sum := frontend.Variable(1)
	for i := 0; i < len(a); i++ {
		d := api.Sub(a[i], b[i])
		t := api.IsZero(d)
		sum = api.And(sum, t)
	}

	return sum
}

// Convert any varialbe to bits first then to U8 array
// Note that if expectedLen is shorter than actual value, the converted value is *not*
// equal to the original value!
// TODO optimization
func byteArrayValueOf[T uints.U32 | uints.U64](api frontend.API, bf *uints.BinaryField[T], a frontend.Variable, expectedLen ...int) []uints.U8 {
	var opt bits.BaseConversionOption
	var bs []frontend.Variable
	if len(expectedLen) == 1 {
		opt = bits.WithNbDigits(expectedLen[0] * 8)
		bs = bits.ToBinary(api, a, opt)
	} else {
		bs = bits.ToBinary(api, a)
	}

	lenBits := len(bs)
	lenBytes := int(math.Ceil(float64(lenBits) / 8.0))

	ret := make([]uints.U8, lenBytes)
	for i := 0; i < lenBytes; i++ {
		b := bs[i*8]
		for j := 1; j < 8 && i*8+j < lenBits; j++ {
			v := bs[i*8+j]
			v = api.Mul(v, 1<<j)
			b = api.Add(b, v)
		}
		ret[i] = bf.ByteValueOf(b)
	}

	return ret
}
