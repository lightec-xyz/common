package utils

import (
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/hash"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion/plonk"
)

// FingerPrint() returns the MiMc hash of the VerifyingKey. It could be used to identify a VerifyingKey
// during recursive verification.
func InCircuitFingerPrint[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](
	api frontend.API, vk *plonk.VerifyingKey[FR, G1El, G2El]) (frontend.Variable, error) {
	var ret frontend.Variable
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return ret, err
	}

	mimc.Write(vk.BaseVerifyingKey.NbPublicVariables)
	mimc.Write(vk.CircuitVerifyingKey.Size)
	mimc.Write(vk.CircuitVerifyingKey.Generator.Limbs[:]...)

	comms := make([]kzg.Commitment[G1El], 0)
	comms = append(comms, vk.CircuitVerifyingKey.S[:]...)
	comms = append(comms, vk.CircuitVerifyingKey.Ql)
	comms = append(comms, vk.CircuitVerifyingKey.Qr)
	comms = append(comms, vk.CircuitVerifyingKey.Qm)
	comms = append(comms, vk.CircuitVerifyingKey.Qo)
	comms = append(comms, vk.CircuitVerifyingKey.Qk)
	comms = append(comms, vk.CircuitVerifyingKey.Qcp[:]...)

	for _, comm := range comms {
		el := comm.G1El
		switch r := any(&el).(type) {
		case *sw_bls12377.G1Affine:
			mimc.Write(r.X)
			mimc.Write(r.Y)
		case *sw_bls12381.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		case *sw_bls24315.G1Affine:
			mimc.Write(r.X)
			mimc.Write(r.Y)
		case *sw_bw6761.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		case *sw_bn254.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		default:
			return ret, fmt.Errorf("unknown parametric type")
		}
	}

	mimc.Write(vk.CircuitVerifyingKey.CommitmentConstraintIndexes[:]...)

	result := mimc.Sum()

	return result, nil
}

func VerifyingKeyMiMCHash[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](h hash.Hash, vk plonk.VerifyingKey[FR, G1El, G2El]) ([]byte, error) {
	mimc := h.New()

	mimc.Write(big.NewInt(int64(vk.BaseVerifyingKey.NbPublicVariables)).Bytes())
	mimc.Write(big.NewInt(int64(vk.CircuitVerifyingKey.Size.(uint64))).Bytes())
	{
		for i := 0; i < len(vk.Generator.Limbs); i++ {
			mimc.Write(vk.Generator.Limbs[i].(*big.Int).Bytes())
		}
	}

	comms := make([]kzg.Commitment[G1El], 0)
	comms = append(comms, vk.CircuitVerifyingKey.S[:]...)
	comms = append(comms, vk.CircuitVerifyingKey.Ql)
	comms = append(comms, vk.CircuitVerifyingKey.Qr)
	comms = append(comms, vk.CircuitVerifyingKey.Qm)
	comms = append(comms, vk.CircuitVerifyingKey.Qo)
	comms = append(comms, vk.CircuitVerifyingKey.Qk)
	comms = append(comms, vk.CircuitVerifyingKey.Qcp[:]...)

	for _, comm := range comms {
		el := comm.G1El
		switch r := any(&el).(type) {
		case *sw_bn254.G1Affine:
			for i := 0; i < len(r.X.Limbs); i++ {
				mimc.Write(r.X.Limbs[i].(*big.Int).Bytes())
			}
			for i := 0; i < len(r.Y.Limbs); i++ {
				mimc.Write(r.Y.Limbs[i].(*big.Int).Bytes())
			}
		default:
			panic("unknown parametric type")
		}
	}

	for i := 0; i < len(vk.CircuitVerifyingKey.CommitmentConstraintIndexes); i++ {
		mimc.Write(big.NewInt(int64(vk.CircuitVerifyingKey.CommitmentConstraintIndexes[i].(uint64))).Bytes())
	}

	result := mimc.Sum(nil)
	return result, nil
}

func UnsafeFingerPrintFromVk[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](vk native_plonk.VerifyingKey) ([]byte, error) {
	circuitVk, err := plonk.ValueOfVerifyingKey[FR, G1El, G2El](vk)
	if err != nil {
		return nil, err
	}
	fpBytes, err := VerifyingKeyMiMCHash[FR, G1El, G2El](hash.MIMC_BN254, circuitVk)
	if err != nil {
		return nil, err
	}
	return fpBytes, nil
}

func UnsafeFingerPrintFromVkFile[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](vkFile string) ([]byte, error) {
	var (
		err     error
		bn254Vk plonk_bn254.VerifyingKey
	)

	fvk, err := os.Open(vkFile)
	if err != nil {
		return nil, err
	}
	defer fvk.Close()
	_, err = bn254Vk.ReadFrom(fvk)
	if err != nil {
		return nil, err
	}
	return UnsafeFingerPrintFromVk[FR, G1El, G2El, GtEl](&bn254Vk)
}

/**
 * FingerPrint[FR] is computed as MiMc(VerifyingKey[FR, ...]), and should be only one field long.
 * When it is used in another field other than where it is computed, it appear as a witness and we should deal with witness in other ways.
 */
type FingerPrint[FR emulated.FieldParams] struct {
	Val frontend.Variable
}

type FingerPrintBytes []byte

func NewFingerPrint[FR emulated.FieldParams](v frontend.Variable) FingerPrint[FR] {
	return FingerPrint[FR]{
		Val: v,
	}
}

func (fp FingerPrint[FR]) AssertIsEqual(api frontend.API, other FingerPrint[FR]) {
	api.AssertIsEqual(fp.Val, other.Val)
}

func (fp FingerPrint[FR]) IsEqual(api frontend.API, other FingerPrint[FR]) frontend.Variable {
	return IsEqual(api, fp.Val, other.Val)
}

func FpValueOf[FR emulated.FieldParams](api frontend.API, v frontend.Variable) FingerPrint[FR] {
	return FingerPrint[FR]{
		Val: v,
	}
}

func FingerPrintFromBytes[FR emulated.FieldParams](data FingerPrintBytes) FingerPrint[FR] {
	var fr FR
	mod := fr.Modulus()
	bitLen := mod.BitLen()
	vals := ValsFromBytes(data, bitLen)
	if len(vals) != 1 {
		panic("fingerprint bytes longer than expected")
	}

	return FingerPrint[FR]{
		Val: vals[0],
	}
}

func TestFpWitness[FR emulated.FieldParams](
	api frontend.API, fp FingerPrint[FR], els []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) frontend.Variable {
	return TestValsVSWtnsElements[FR](api, []frontend.Variable{fp.Val}, els, nbMaxBitsPerVar...)
}

func AssertFpWitness[FR emulated.FieldParams](
	api frontend.API, fp FingerPrint[FR], els []emulated.Element[FR], nbMaxBitsPerVar ...uint,
) {
	AssertValsVSWtnsElements[FR](api, []frontend.Variable{fp.Val}, els, nbMaxBitsPerVar...)
}

func TestFpInFpSet[FR emulated.FieldParams](api frontend.API, fp frontend.Variable, fpSet []FingerPrint[FR]) frontend.Variable {
	fpv := FpValueOf[FR](api, fp)

	sum := frontend.Variable(0)
	for i := 0; i < len(fpSet); i++ {
		t := fpv.IsEqual(api, fpSet[i])
		sum = api.Or(t, sum)
	}
	return sum
}

func AssertFpInFpSet[FR emulated.FieldParams](api frontend.API, fp frontend.Variable, fpSet []FingerPrint[FR]) {
	sum := TestFpInFpSet[FR](api, fp, fpSet)
	api.AssertIsEqual(sum, 1)
}

func TestFpInSet[FR emulated.FieldParams](api frontend.API, fp frontend.Variable, fpSet []FingerPrintBytes) frontend.Variable {
	set := bytesSetToFpSet[FR](fpSet)
	return TestFpInFpSet[FR](api, fp, set)
}

func AssertFpInSet[FR emulated.FieldParams](api frontend.API, fp frontend.Variable, fpSet []FingerPrintBytes) {
	sum := TestFpInSet[FR](api, fp, fpSet)
	api.AssertIsEqual(sum, 1)
}

func bytesSetToFpSet[FR emulated.FieldParams](bytesSet []FingerPrintBytes) []FingerPrint[FR] {
	ret := make([]FingerPrint[FR], len(bytesSet))
	for i := 0; i < len(ret); i++ {
		ret[i] = FingerPrintFromBytes[FR](bytesSet[i])
	}
	return ret
}
