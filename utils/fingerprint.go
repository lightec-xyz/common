package utils

import (
	"math/big"
	"os"
	"slices"

	"github.com/consensys/gnark-crypto/hash"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/commitments/kzg"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
)

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
	slices.Reverse(result)
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

type FingerPrint struct {
	Vals       []frontend.Variable
	BitsPerVar int
}

type FingerPrintBytes []byte

func NewFingerPrint(v []frontend.Variable, b int) FingerPrint {
	return FingerPrint{
		Vals:       v,
		BitsPerVar: b,
	}
}
func PlaceholderFingerPrint(nbVars, bitsPerVar int) FingerPrint {
	return FingerPrint{
		Vals:       make([]frontend.Variable, nbVars),
		BitsPerVar: bitsPerVar,
	}
}
func (fp FingerPrint) AssertIsEqual(api frontend.API, other FingerPrint) {
	api.AssertIsEqual(fp.BitsPerVar, other.BitsPerVar)
	api.AssertIsEqual(len(fp.Vals), len(other.Vals))
	for i := 0; i < len(fp.Vals); i++ {
		api.AssertIsEqual(fp.Vals[i], other.Vals[i])
	}
}
func (fp FingerPrint) IsEqual(api frontend.API, other FingerPrint) frontend.Variable {
	api.AssertIsEqual(fp.BitsPerVar, other.BitsPerVar)
	return areVarsEquals(api, fp.Vals, other.Vals)
}

func FpValueOf(api frontend.API, v frontend.Variable, bitsPerVar int) (FingerPrint, error) {
	bits := api.ToBinary(v)

	vals := bitsToVars(api, bits, bitsPerVar)
	return FingerPrint{
		Vals:       vals,
		BitsPerVar: bitsPerVar,
	}, nil
}

func TestVkeyFp[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](
	api frontend.API, vkey plonk.VerifyingKey[FR, G1El, G2El], otherFp FingerPrint) (frontend.Variable, error) {

	fpVar, err := vkey.FingerPrint(api)
	if err != nil {
		return 0, err
	}
	fp, err := FpValueOf(api, fpVar, otherFp.BitsPerVar)
	if err != nil {
		return 0, err
	}
	return fp.IsEqual(api, otherFp), nil
}

func FingerPrintFromBytes(data FingerPrintBytes, bitsPerVar int) FingerPrint {
	return FingerPrint{
		Vals:       ValsFromBytes(data, bitsPerVar),
		BitsPerVar: bitsPerVar,
	}
}

func AssertFpInSet(api frontend.API, fp frontend.Variable, fpSet []FingerPrintBytes, fpBitsPerVar int) {
	fpv, err := FpValueOf(api, fp, fpBitsPerVar)
	if err != nil {
		panic(err)
	}

	sum := frontend.Variable(0)
	for i := 0; i < len(fpSet); i++ {
		v := FingerPrintFromBytes(fpSet[i], fpBitsPerVar)
		t := fpv.IsEqual(api, v)
		sum = api.Or(t, sum)
	}
	api.AssertIsEqual(sum, 1)
}

func ValsToU8s(api frontend.API, vals []frontend.Variable, bitsPerVar int) ([]uints.U8, error) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	bytesPerVar := bitsPerVar / 8
	ret := make([]uints.U8, bytesPerVar*len(vals))
	for i := 0; i < len(vals); i++ {
		bytes := uapi.ByteArrayValueOf(vals[i], bytesPerVar)
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

func areVarsEquals(api frontend.API, a, b []frontend.Variable) frontend.Variable {
	api.AssertIsEqual(len(a), len(b))
	sum := frontend.Variable(1)
	for i := 0; i < len(a); i++ {
		d := api.Sub(a[i], b[i])
		t := api.IsZero(d)
		sum = api.And(sum, t)
	}

	return sum
}

func bitsToVars(api frontend.API, bits []frontend.Variable, bitsPerVar int) []frontend.Variable {

	vals := make([]frontend.Variable, 0)
	for i := 0; i < len(bits); i += bitsPerVar {
		val := api.FromBinary(bits[i : i+bitsPerVar]...)
		vals = append(vals, val)
	}

	slices.Reverse[[]frontend.Variable](vals)
	return vals
}
