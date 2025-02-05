package utils

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type byteArrayValueOfCircuitWithSpecifiedLen struct {
	In       frontend.Variable
	Expected []uints.U8
}

func (c *byteArrayValueOfCircuitWithSpecifiedLen) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	res := byteArrayValueOf(api, uapi, c.In, 3)
	api.AssertIsEqual(len(res), len(c.Expected))
	for i := 0; i < len(res); i++ {
		uapi.ByteAssertEq(res[i], c.Expected[i])
	}

	return nil
}

func TestByteArrayValueOfWithSpecifiedLen(t *testing.T) {
	assert := test.NewAssert(t)
	a, b, c := 13, 17, 19
	p := a + (b << 8) + (c << 16)
	expected := uints.NewU8Array([]uint8{uint8(a), uint8(b), uint8(c)})

	circuit := &byteArrayValueOfCircuitWithSpecifiedLen{
		Expected: expected,
	}
	assignment := &byteArrayValueOfCircuitWithSpecifiedLen{
		In:       frontend.Variable(p),
		Expected: expected,
	}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type byteArrayValueOfCircuitWithoutSpecifiedLen struct {
	In       frontend.Variable
	Expected []uints.U8
}

func (c *byteArrayValueOfCircuitWithoutSpecifiedLen) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	res := byteArrayValueOf(api, uapi, c.In)
	for i := 0; i < len(c.Expected); i++ {
		uapi.ByteAssertEq(res[i], c.Expected[i])
	}
	for i := len(c.Expected); i < len(res); i++ {
		uapi.ByteAssertEq(res[i], uints.NewU8(0))
	}

	return nil
}

func TestByteArrayValueOfWithoutSpecifiedLen(t *testing.T) {
	assert := test.NewAssert(t)
	a, b, c := 13, 17, 19
	p := a + (b << 8) + (c << 16)
	expected := uints.NewU8Array([]uint8{uint8(a), uint8(b), uint8(c)})

	circuit := &byteArrayValueOfCircuitWithoutSpecifiedLen{
		Expected: expected,
	}
	assignment := &byteArrayValueOfCircuitWithoutSpecifiedLen{
		In:       frontend.Variable(p),
		Expected: expected,
	}

	err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
