package operations

import (
	"fmt"
	"math/bits"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func OpenFileOnCreaterOverwrite(file string) (*os.File, error) {
	// 获取目录的状态信息
	dir := filepath.Dir(file)
	_, err := os.Stat(dir)
	if err != nil {
		// 如果目录不存在，则创建目录
		if os.IsNotExist(err) {
			err = os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	exists, err := FileExists(file)
	if err != nil {
		return nil, err
	}

	if exists {
		err := os.Remove(file)
		if err != nil {
			return nil, err
		}
	}

	fFile, err := os.Create(file)
	if err != nil {
		return nil, err
	}

	return fFile, nil
}

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
	openFile, err := OpenFileOnCreaterOverwrite(fn)
	if err != nil {
		return err
	}
	defer openFile.Close()

	_, err = pk.WriteTo(openFile)
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
	openFile, err := OpenFileOnCreaterOverwrite(fn)
	if err != nil {
		return err
	}
	defer openFile.Close()

	_, err = vk.WriteTo(openFile)
	if err != nil {
		return err
	}

	return nil
}

func WriteSolidity(vk plonk.VerifyingKey, fn string) error {
	openFile, err := OpenFileOnCreaterOverwrite(fn)
	if err != nil {
		return err
	}
	defer openFile.Close()

	err = vk.ExportSolidity(openFile)
	if err != nil {
		return err
	}
	return nil
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
	openFile, err := OpenFileOnCreaterOverwrite(fn)
	if err != nil {
		return err
	}
	defer openFile.Close()

	_, err = ccs.WriteTo(openFile)
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
	openFile, err := OpenFileOnCreaterOverwrite(fn)
	if err != nil {
		return err
	}
	defer openFile.Close()

	_, err = proof.WriteTo(openFile)
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
	openFile, err := OpenFileOnCreaterOverwrite(fn)
	if err != nil {
		return err
	}
	defer openFile.Close()

	//suppose wtns should only have public ones, but if all witness are given, extract only public ones
	pubWit, err := wit.Public()
	if err != nil {
		return err
	}

	_, err = pubWit.WriteTo(openFile)
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
