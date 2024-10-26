package operations

import (
	"fmt"
	"math/bits"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
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
