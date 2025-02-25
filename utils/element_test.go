package utils

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"
)

type U254ToElementCircuit struct {
	MinerReward frontend.Variable
	minerReward [32]byte
}

func newElementFromU254(field *emulated.Field[emparams.BN254Fp], api frontend.API, v frontend.Variable) *emulated.Element[emparams.BN254Fp] {
	bits := api.ToBinary(v, 254)
	return field.FromBits(bits...)
}

func (c *U254ToElementCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.MinerReward, c.minerReward[:])

	field, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return err
	}

	expected := field.NewElement(c.minerReward[:])
	actual := newElementFromU254(field, api, c.MinerReward)
	field.AssertIsEqual(actual, expected)

	minerReward := RetrieveU254ValueFromElement(api, *actual)
	api.AssertIsEqual(minerReward, c.minerReward[:])

	return nil
}

func TestU254ToElementCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	minerReward, err := hex.DecodeString("0b00000a000000300000500000400000060000090000080800009184e72a0000")
	assert.NoError(err)

	circuit := &U254ToElementCircuit{
		minerReward: [32]byte(minerReward),
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	assert.NoError(err)

	t.Logf("nbConstraints: %v, nbSecret: %v, nbPublic: %v\n",
		cs.GetNbConstraints(), cs.GetNbSecretVariables(), cs.GetNbPublicVariables())

	assignment := &U254ToElementCircuit{
		MinerReward: minerReward,
	}

	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type U8RangeCheck struct {
	Value uints.U8
}

func (c *U8RangeCheck) Define(api frontend.API) error {
	r := frontend.Variable(200)
	rcheck := rangecheck.New(api)
	rcheck.Check(r, 8)
	return nil
}

func TestU8Circuit(t *testing.T) {
	assert := test.NewAssert(t)

	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, scs.NewBuilder, &U8RangeCheck{})
	assert.NoError(err)

	t.Logf("nbConstraints: %v, nbSecret: %v, nbPublic: %v\n",
		ccs.GetNbConstraints(), ccs.GetNbSecretVariables(), ccs.GetNbPublicVariables())
}
