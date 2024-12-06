package operations

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func ReadPk(fn string) (plonk.ProvingKey, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pk := plonk.NewProvingKey(ecc.BN254)
	pk.ReadFrom(f)
	return pk, nil
}

func WritePk(pk plonk.ProvingKey, fn string) error {
	exists, err := FileExists(fn)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(fn)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = pk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func ReadVk(fn string) (plonk.VerifyingKey, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(f)

	// recursiveVk, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
	// if err != nil {
	// 	panic(err)
	// }

	return vk, nil
}

func WriteVk(vk plonk.VerifyingKey, fn string) error {
	exists, err := FileExists(fn)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(fn)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = vk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func WriteSolidity(vk plonk.VerifyingKey, fn string) error {
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()

	return vk.ExportSolidity(f)
}

func ReadCcs(fn string) (constraint.ConstraintSystem, error) {
	var ccs cs_bn254.SparseR1CS
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = ccs.ReadFrom(f)
	if err != nil {
		return nil, err
	}

	return &ccs, nil
}

func WriteCcs(ccs constraint.ConstraintSystem, fn string) error {
	exists, err := FileExists(fn)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(fn)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = ccs.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func ReadProof(fn string) (plonk.Proof, error) {
	var bn254Proof plonk_bn254.Proof
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = bn254Proof.ReadFrom(f)
	if err != nil {
		return nil, err
	}
	return &bn254Proof, nil
}

func WriteProof(proof plonk.Proof, fn string) error {
	exists, err := FileExists(fn)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(fn)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = proof.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func WriteProofInSolidity(proof plonk.Proof, fn string) error {
	exists, err := FileExists(fn)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(fn)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()

	_proof := proof.(*plonk_bn254.Proof)
	proofStr := hex.EncodeToString(_proof.MarshalSolidity())

	_, err = f.WriteString(proofStr)
	if err != nil {
		return err
	}

	return nil
}

func ReadWitness(fn string) (witness.Witness, error) {
	field := ecc.BN254.ScalarField()
	var (
		wit witness.Witness
	)
	wit, err := witness.New(field)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = wit.ReadFrom(f)
	if err != nil {
		return nil, err
	}

	return wit, nil
}

func WriteWitness(wit witness.Witness, fn string) error {
	pub, err := wit.Public()
	if err != nil {
		return err
	}
	exists, err := FileExists(fn)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(fn)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = pub.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func WriteWitnessInJson(wit witness.Witness, fn string) error {
	pub, err := wit.Public()
	if err != nil {
		return err
	}
	exists, err := FileExists(fn)
	if err != nil {
		return err
	}
	if exists {
		err := os.Remove(fn)
		if err != nil {
			return err
		}
	}
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	defer f.Close()

	pubStr := fmt.Sprintf("%v", pub.Vector())
	_, err = f.WriteString(pubStr)
	if err != nil {
		return err
	}
	return nil
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat error: %v", err)
}

func Power2Index(n uint64) int {
	c := bits.OnesCount64(n)
	if c != 1 {
		panic("n must be 2^k")
	}

	t := bits.LeadingZeros64(n)
	if t == 0 {
		panic("next power of 2 overflows uint64")
	}
	return 63 - t
}

func ReadSrs(size int, srsDir string) (*kzg.SRS, *kzg.SRS, error) {
	srs := kzg.NewSRS(ecc.BN254)
	srsLagrange := kzg.NewSRS(ecc.BN254)

	sizeLagrange := ecc.NextPowerOfTwo(uint64(size))
	index := Power2Index(sizeLagrange)
	srsFile := filepath.Join(srsDir, fmt.Sprintf("bn254_pow_%v.srs", index))
	lagrangeSrsFile := filepath.Join(srsDir, fmt.Sprintf("bn254_pow_%v.lsrs", index))

	fsrs, err := os.Open(srsFile)
	if err != nil {
		return nil, nil, err
	}
	defer fsrs.Close()
	flsrs, err := os.Open(lagrangeSrsFile)
	if err != nil {
		return nil, nil, err
	}
	defer flsrs.Close()

	_, err = srs.ReadFrom(fsrs)
	if err != nil {
		return nil, nil, err
	}
	if len(srs.(*kzg_bn254.SRS).Pk.G1) != int(sizeLagrange+3) {
		return nil, nil, fmt.Errorf("incorrect srs size")
	}

	_, err = srsLagrange.ReadFrom(flsrs)
	if err != nil {
		return nil, nil, err
	}
	if len(srsLagrange.(*kzg_bn254.SRS).Pk.G1) != int(sizeLagrange) {
		return nil, nil, fmt.Errorf("incorrect srs lagrange size")
	}
	return &srs, &srsLagrange, nil
}
