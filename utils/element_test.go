package utils

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type RetrieveU254Circuit struct {
	Value frontend.Variable
}

func (c *RetrieveU254Circuit) Define(api frontend.API) error {
	var fr sw_bn254.BaseField
	field, _ := emulated.NewField[sw_bn254.BaseField](api)
	element := field.NewElement(frontend.Variable(fr.Modulus()))
	RetrieveU254ValueFromElement[sw_bn254.BaseField](api, *element)
	return nil
}

func TestRetrieveU254Circuit(t *testing.T) {
	field := ecc.BN254.ScalarField()
	ccs, _ := frontend.Compile(field, scs.NewBuilder, &RetrieveU254Circuit{})

	fmt.Printf("nbConstraints: %v, nbSecret: %v, nbPublic: %v\n", ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables())
}

type U8RangeCheck struct {
	Value uints.U8
}

func (c *U8RangeCheck) Define(api frontend.API) error {
	r := frontend.Variable(200)
	rcheck := rangecheck.New(api)
	rcheck.Check(r, 8)
	rcheck.Check(r, 8)
	return nil
}

func TestU8Circuit(t *testing.T) {
	assert := test.NewAssert(t)

	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, scs.NewBuilder, &U8RangeCheck{})
	assert.NoError(err)

	fmt.Printf("nbConstraints: %v, nbSecret: %v, nbPublic: %v\n", ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables())
}
