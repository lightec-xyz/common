package utils

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

type OuterCircuitDual[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proofs         []recursive_plonk.Proof[FR, G1El, G2El]
	VerifyingKeys  []recursive_plonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"`
	InnerWitnesses []recursive_plonk.Witness[FR]                  `gnark:",public"`
	RawFpBytes     FingerPrintBytes
}

func (c *OuterCircuitDual[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := recursive_plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKeys[0], c.Proofs[0], c.InnerWitnesses[0], recursive_plonk.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	fp, err := InCircuitFingerPrint[FR, G1El, G2El](api, &c.VerifyingKeys[0])
	if err != nil {
		return fmt.Errorf("new curve for verification keys: %w", err)
	}
	api.Println(fp)

	err = verifier.AssertProof(c.VerifyingKeys[1], c.Proofs[1], c.InnerWitnesses[1], recursive_plonk.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	fp2, err := InCircuitFingerPrint[FR, G1El, G2El](api, &c.VerifyingKeys[1])
	if err != nil {
		return fmt.Errorf("new curve for verification keys: %w", err)
	}
	api.Println(fp2)
	// same constant value should result same verification key
	api.AssertIsEqual(fp, fp2)

	err = verifier.AssertProof(c.VerifyingKeys[2], c.Proofs[2], c.InnerWitnesses[2], recursive_plonk.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	fp3, err := InCircuitFingerPrint[FR, G1El, G2El](api, &c.VerifyingKeys[2])
	if err != nil {
		return fmt.Errorf("new curve for verification keys: %w", err)
	}
	api.Println(fp3)
	// different constant values should result in different verification keys
	api.AssertIsDifferent(fp, fp3)

	// consistency check: in-cuicuit computed vkey hash must match out-circuit computation
	fpFromBytes := FingerPrintFromBytes[sw_bn254.ScalarField](c.RawFpBytes)
	fpFromBytes.AssertIsEqual(api, FingerPrint[sw_bn254.ScalarField]{Val: fp})

	return err
}

// the constant value (c.multiplier) should impact not only the relationship between X and Y
// but also the circuit structure, meaning the vkey fingerprint will *change* with a different constant value
type InnerCircuitWithConstant struct {
	X          frontend.Variable
	Y          frontend.Variable `gnark:",public"`
	multiplier int
}

func (c *InnerCircuitWithConstant) Define(api frontend.API) error {
	res := api.Mul(c.X, c.multiplier)
	api.AssertIsEqual(res, c.Y)

	return nil
}

func getInnerCircuitProof(assert *test.Assert, field, outer *big.Int) ([]constraint.ConstraintSystem, []native_plonk.VerifyingKey, []witness.Witness, []native_plonk.Proof) {

	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitWithConstant{multiplier: 5})
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)
	assert.NoError(err)

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)

	// inner proof
	innerAssignment := &InnerCircuitWithConstant{
		X: 3,
		Y: 15,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, recursive_plonk.GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, recursive_plonk.GetNativeVerifierOptions(outer, field))

	assert.NoError(err)

	// innerCcs is only needed for nbConstraints/nbPublicVarialbes and .Field()
	// so we could reuse generated srs for another CCS instance which only differs in the constant multiplier
	innerCcs2, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitWithConstant{multiplier: 5})
	assert.NoError(err)

	innerPK2, innerVK2, err := native_plonk.Setup(innerCcs2, srs, srsLagrange)
	assert.NoError(err)

	// inner proof2
	innerAssignment2 := &InnerCircuitWithConstant{
		X: 3,
		Y: 15,
	}
	innerWitness2, err := frontend.NewWitness(innerAssignment2, field)
	assert.NoError(err)
	innerProof2, err := native_plonk.Prove(innerCcs2, innerPK2, innerWitness2, recursive_plonk.GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness2, err := innerWitness2.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof2, innerVK2, innerPubWitness2, recursive_plonk.GetNativeVerifierOptions(outer, field))

	assert.NoError(err)

	innerCcs3, err := frontend.Compile(field, scs.NewBuilder, &InnerCircuitWithConstant{multiplier: 7})
	assert.NoError(err)

	innerPK3, innerVK3, err := native_plonk.Setup(innerCcs3, srs, srsLagrange)
	assert.NoError(err)

	// inner proof3
	innerAssignment3 := &InnerCircuitWithConstant{
		X: 3,
		Y: 21,
	}
	innerWitness3, err := frontend.NewWitness(innerAssignment3, field)
	assert.NoError(err)
	innerProof3, err := native_plonk.Prove(innerCcs3, innerPK3, innerWitness3, recursive_plonk.GetNativeProverOptions(outer, field))

	assert.NoError(err)
	innerPubWitness3, err := innerWitness3.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof3, innerVK3, innerPubWitness3, recursive_plonk.GetNativeVerifierOptions(outer, field))

	assert.NoError(err)

	return []constraint.ConstraintSystem{innerCcs, innerCcs2, innerCcs3},
		[]native_plonk.VerifyingKey{innerVK, innerVK2, innerVK3},
		[]witness.Witness{innerPubWitness, innerPubWitness2, innerPubWitness3},
		[]native_plonk.Proof{innerProof, innerProof2, innerProof3}
}

func TestBW6InBN254VkeyFp(t *testing.T) {
	testVkeyFp[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl, sw_bn254.ScalarField](t)
}

func TestBN254InBN254VkeyFp(t *testing.T) {
	testVkeyFp[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl, sw_bn254.ScalarField](t)
}

func TestBls12381InBN254VkeyFp(t *testing.T) {
	testVkeyFp[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl, sw_bn254.ScalarField](t)
}

func testVkeyFp[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT, FROuter emulated.FieldParams](
	t *testing.T) {

	var fr FR
	var outerFr FROuter

	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInnerCircuitProof(assert, fr.Modulus(), outerFr.Modulus())

	// outer proofs
	circuitVk, err := recursive_plonk.ValueOfVerifyingKey[FR, G1El, G2El](innerVK[0])
	assert.NoError(err)
	circuitWitness, err := recursive_plonk.ValueOfWitness[FR](innerWitness[0])
	assert.NoError(err)
	circuitProof, err := recursive_plonk.ValueOfProof[FR, G1El, G2El](innerProof[0])
	assert.NoError(err)

	circuitVkFp, err := UnsafeFingerPrintFromVk[FROuter](innerVK[0])
	assert.NoError(err)

	circuitVk2, err := recursive_plonk.ValueOfVerifyingKey[FR, G1El, G2El](innerVK[1])
	assert.NoError(err)
	circuitWitness2, err := recursive_plonk.ValueOfWitness[FR](innerWitness[1])
	assert.NoError(err)
	circuitProof2, err := recursive_plonk.ValueOfProof[FR, G1El, G2El](innerProof[1])
	assert.NoError(err)

	circuitVk3, err := recursive_plonk.ValueOfVerifyingKey[FR, G1El, G2El](innerVK[2])
	assert.NoError(err)
	circuitWitness3, err := recursive_plonk.ValueOfWitness[FR](innerWitness[2])
	assert.NoError(err)
	circuitProof3, err := recursive_plonk.ValueOfProof[FR, G1El, G2El](innerProof[2])
	assert.NoError(err)

	outerCircuit := &OuterCircuitDual[FR, G1El, G2El, GtEl]{
		InnerWitnesses: []recursive_plonk.Witness[FR]{
			recursive_plonk.PlaceholderWitness[FR](innerCcs[0]),
			recursive_plonk.PlaceholderWitness[FR](innerCcs[1]),
			recursive_plonk.PlaceholderWitness[FR](innerCcs[2]),
		},
		Proofs: []recursive_plonk.Proof[FR, G1El, G2El]{
			recursive_plonk.PlaceholderProof[FR, G1El, G2El](innerCcs[0]),
			recursive_plonk.PlaceholderProof[FR, G1El, G2El](innerCcs[1]),
			recursive_plonk.PlaceholderProof[FR, G1El, G2El](innerCcs[2]),
		},
		VerifyingKeys: []recursive_plonk.VerifyingKey[FR, G1El, G2El]{
			circuitVk,
			circuitVk2,
			circuitVk3,
		},
		RawFpBytes: circuitVkFp,
	}
	outerAssignment := &OuterCircuitDual[FR, G1El, G2El, GtEl]{
		InnerWitnesses: []recursive_plonk.Witness[FR]{circuitWitness, circuitWitness2, circuitWitness3},
		Proofs:         []recursive_plonk.Proof[FR, G1El, G2El]{circuitProof, circuitProof2, circuitProof3},
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
