package utils

import (
	"encoding/binary"
	"fmt"
	"hash"
	"os"

	mimc_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	mimc_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	mimc_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/mimc"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	mimc_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	plonk_bw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
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

	allU64s := make([]frontend.Variable, 0)
	allU64s = append(allU64s, vk.BaseVerifyingKey.NbPublicVariables)
	allU64s = append(allU64s, vk.CircuitVerifyingKey.Size)

	elements := make([]frontend.Variable, 0)
	vk.CircuitVerifyingKey.Generator.Initialize(api.Compiler().Field())
	elements = append(elements, vk.CircuitVerifyingKey.Generator.Limbs[:]...)

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
		var fr FR
		switch r := any(&el).(type) {
		case *sw_bls12381.G1Affine:
			r.X.Initialize(fr.Modulus())
			r.Y.Initialize(fr.Modulus())
			elements = append(elements, r.X.Limbs[:]...)
			elements = append(elements, r.Y.Limbs[:]...)
		case *sw_bw6761.G1Affine:
			r.X.Initialize(fr.Modulus())
			r.Y.Initialize(fr.Modulus())
			elements = append(elements, r.X.Limbs[:]...)
			elements = append(elements, r.Y.Limbs[:]...)
		case *sw_bn254.G1Affine:
			r.X.Initialize(fr.Modulus())
			r.Y.Initialize(fr.Modulus())
			elements = append(elements, r.X.Limbs[:]...)
			elements = append(elements, r.Y.Limbs[:]...)
		default:
			return ret, fmt.Errorf("unknown parametric type")
		}
	}

	allU64s = append(allU64s, vk.CircuitVerifyingKey.CommitmentConstraintIndexes[:]...)

	mimc, err := mimc.NewMiMC(api) // the default field is determined by the information from api
	if err != nil {
		return ret, err
	}
	for _, u64 := range allU64s {
		mimc.Write(u64)
	}
	for _, element := range elements {
		mimc.Write(element)
	}
	result := mimc.Sum()

	return result, nil
}

func UnsafeFingerPrintFromVk[FR emulated.FieldParams](vk native_plonk.VerifyingKey) (FingerPrintBytes, error) {
	var fr FR
	var hash hash.Hash
	switch any(&fr).(type) {
	case *sw_bw6761.ScalarField:
		hash = mimc_bw6761.NewMiMC()
	case *sw_bn254.ScalarField:
		hash = mimc_bn254.NewMiMC()
	case *sw_bls12381.ScalarField:
		hash = mimc_bls12381.NewMiMC()
	case *sw_bls12377.ScalarField:
		hash = mimc_bls12377.NewMiMC()
	case *sw_bls24315.ScalarField:
		hash = mimc_bls24315.NewMiMC()
	default:
		return nil, fmt.Errorf("unknown parametric type for %d", fr.Modulus())
	}

	// element limbs in montgomery form, we could marshall first

	elements := make([][]byte, 0)
	nums := make([]uint64, 0)
	switch r := any(vk).(type) {
	case *plonk_bls12381.VerifyingKey:
		nums = append(nums, r.NbPublicVariables)
		nums = append(nums, r.Size)
		elements = append(elements, r.Generator.Marshal())
		for _, s := range r.S {
			elements = append(elements, s.X.Marshal())
			elements = append(elements, s.Y.Marshal())
		}
		elements = append(elements, r.Ql.X.Marshal())
		elements = append(elements, r.Ql.Y.Marshal())
		elements = append(elements, r.Qr.X.Marshal())
		elements = append(elements, r.Qr.Y.Marshal())
		elements = append(elements, r.Qm.X.Marshal())
		elements = append(elements, r.Qm.Y.Marshal())
		elements = append(elements, r.Qo.X.Marshal())
		elements = append(elements, r.Qo.Y.Marshal())
		elements = append(elements, r.Qk.X.Marshal())
		elements = append(elements, r.Qk.Y.Marshal())
		for _, c := range r.Qcp {
			elements = append(elements, c.X.Marshal())
			elements = append(elements, c.Y.Marshal())
		}
		nums = append(nums, r.CommitmentConstraintIndexes...)
	case *plonk_bw6761.VerifyingKey:
		nums = append(nums, r.NbPublicVariables)
		nums = append(nums, r.Size)
		elements = append(elements, r.Generator.Marshal())
		for _, s := range r.S {
			elements = append(elements, s.X.Marshal())
			elements = append(elements, s.Y.Marshal())
		}
		elements = append(elements, r.Ql.X.Marshal())
		elements = append(elements, r.Ql.Y.Marshal())
		elements = append(elements, r.Qr.X.Marshal())
		elements = append(elements, r.Qr.Y.Marshal())
		elements = append(elements, r.Qm.X.Marshal())
		elements = append(elements, r.Qm.Y.Marshal())
		elements = append(elements, r.Qo.X.Marshal())
		elements = append(elements, r.Qo.Y.Marshal())
		elements = append(elements, r.Qk.X.Marshal())
		elements = append(elements, r.Qk.Y.Marshal())
		for _, c := range r.Qcp {
			elements = append(elements, c.X.Marshal())
			elements = append(elements, c.Y.Marshal())
		}
		nums = append(nums, r.CommitmentConstraintIndexes...)
	case *plonk_bn254.VerifyingKey:
		nums = append(nums, r.NbPublicVariables)
		nums = append(nums, r.Size)
		elements = append(elements, r.Generator.Marshal())
		for _, s := range r.S {
			elements = append(elements, s.X.Marshal())
			elements = append(elements, s.Y.Marshal())
		}
		elements = append(elements, r.Ql.X.Marshal())
		elements = append(elements, r.Ql.Y.Marshal())
		elements = append(elements, r.Qr.X.Marshal())
		elements = append(elements, r.Qr.Y.Marshal())
		elements = append(elements, r.Qm.X.Marshal())
		elements = append(elements, r.Qm.Y.Marshal())
		elements = append(elements, r.Qo.X.Marshal())
		elements = append(elements, r.Qo.Y.Marshal())
		elements = append(elements, r.Qk.X.Marshal())
		elements = append(elements, r.Qk.Y.Marshal())
		for _, c := range r.Qcp {
			elements = append(elements, c.X.Marshal())
			elements = append(elements, c.Y.Marshal())
		}
		nums = append(nums, r.CommitmentConstraintIndexes...)
	default:
		return nil, fmt.Errorf("unknown parametric type")
	}

	for _, num := range nums {
		b8 := make([]byte, 8)
		binary.BigEndian.PutUint64(b8, num)
		hash.Write(b8)
	}

	for _, elementBytes := range elements {
		for l := len(elementBytes) / 8; l > 0; l-- {
			hash.Write(elementBytes[(l-1)*8 : l*8])
		}
	}

	result := hash.Sum(nil)

	return result, nil

}

func UnsafeFingerPrintFromVkFile[FR emulated.FieldParams](vkFile string) (FingerPrintBytes, error) {
	var (
		err     error
		bn254Vk plonk_bn254.VerifyingKey
	)

	fvk, err := os.Open(vkFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = fvk.Close()
	}()
	_, err = bn254Vk.ReadFrom(fvk)
	if err != nil {
		return nil, err
	}
	return UnsafeFingerPrintFromVk[FR](&bn254Vk)
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
