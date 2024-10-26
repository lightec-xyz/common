package operations

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark-crypto/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/lightec-xyz/chainark"
	"github.com/lightec-xyz/common/utils"
	"github.com/rs/zerolog"
)

type CircuitOperations struct {
	ProvingKey    native_plonk.ProvingKey
	VerifyingKey  native_plonk.VerifyingKey
	Ccs           constraint.ConstraintSystem
	Config        *Config
	ComponentName string
	Logger        *zerolog.Logger
}

func (c *CircuitOperations) SetupWithCircuit(circuit frontend.Circuit) (constraint.ConstraintSystem, native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {
	log := logger.Logger().With().Str("component", c.ComponentName).Logger()
	ccs, err := NewConstraintSystem(circuit)
	if err != nil {
		log.Error().Msgf("failed to new %v constraint system: %v", c.ComponentName, err)
		return nil, nil, nil, err
	}

	srs, lsrs, err := ReadSrs(ccs.GetNbConstraints()+ccs.GetNbPublicVariables(), c.Config.SrsDir)
	if err != nil {
		log.Error().Msgf("failed to read srs: %v", err)
		return nil, nil, nil, err
	}

	pk, vk, err := PlonkSetup(ccs, srs, lsrs)
	if err != nil {
		log.Error().Msgf("failed to init %v pk vk: %v", c.ComponentName, err)
		return nil, nil, nil, err
	}
	c.Ccs = ccs
	c.ProvingKey = pk
	c.VerifyingKey = vk
	c.Logger = &log
	return ccs, pk, vk, nil
}

func (c *CircuitOperations) LoadCcsPkVk() error {
	log := logger.Logger().With().Str("component", c.ComponentName).Logger()
	c.Logger = &log
	ccs, err := ReadCcs(c.Config.CcsFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to read %v ccs: %v", c.ComponentName, err)
		return err
	}
	pk, err := ReadPk(c.Config.PkFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to read %v pk: %v", c.ComponentName, err)
		return err
	}
	vk, err := ReadVk(c.Config.VkFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to read %v vk: %v", c.ComponentName, err)
		return err
	}
	c.Ccs = ccs
	c.ProvingKey = pk
	c.VerifyingKey = vk

	return nil
}

func (c *CircuitOperations) ProveWithAssignment(assignment frontend.Circuit, isFront bool) (*Proof, error) {
	proof, wit, err := PlonkProve(assignment, c.ProvingKey, c.Ccs, isFront)
	if err != nil {
		c.Logger.Error().Msgf("failed to prove %v: %v", c.ComponentName, err)
		return nil, err
	}
	err = PlonkVerify(c.VerifyingKey, proof, wit, isFront)
	if err != nil {
		c.Logger.Error().Msgf("failed to verify %v: %v", c.ComponentName, err)
		return nil, err
	}
	return &Proof{
		Proof: proof,
		Wit:   wit,
	}, nil
}

func (c *CircuitOperations) SaveCcsPkVk(ccsFile, pkFile, vkFile string) error {
	err := WriteCcs(c.Ccs, ccsFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to write %v ccs: %v", c.ComponentName, err)
		return err
	}
	err = WritePk(c.ProvingKey, pkFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to write %v pk: %v", c.ComponentName, err)
		return err
	}
	err = WriteVk(c.VerifyingKey, vkFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to write %v vk: %v", c.ComponentName, err)
		return err
	}
	return nil
}

func (c *CircuitOperations) SaveProofAndWitness(proof *Proof, proofFile, witnessFile string) error {
	err := WriteProof(proof.Proof, proofFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to write %v proof: %v", c.ComponentName, err)
		return err
	}

	err = WriteWitness(proof.Wit, witnessFile)
	if err != nil {
		c.Logger.Error().Msgf("failed to write %v witness: %v", c.ComponentName, err)
		return err
	}
	return nil
}

func (c *CircuitOperations) GetVerifyingKey() (native_plonk.VerifyingKey, error) {
	if c.VerifyingKey == nil {
		verifyingKey, err := ReadVk(c.Config.VkFile)
		if err != nil {
			c.Logger.Error().Msgf("failed to get %v vk: %v", c.ComponentName, err)
			return nil, err
		}
		c.VerifyingKey = verifyingKey
	}
	return c.VerifyingKey, nil
}

func (c *CircuitOperations) UnsafeFingerPrint() ([]byte, error) {
	verifyingKey, err := c.GetVerifyingKey()
	if err != nil {
		c.Logger.Error().Msgf("failed to get %v vk: %v", c.ComponentName, err)
		return nil, err
	}
	vkFigurePrint, err := utils.UnsafeFingerPrintFromVk[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](verifyingKey)
	if err != nil {
		c.Logger.Error().Msgf("failed to get %v fingerprint: %v", c.ComponentName, err)
		return nil, err
	}
	return vkFigurePrint, nil
}

func (c *CircuitOperations) ConstraintSystem() (constraint.ConstraintSystem, error) {
	if c.Ccs == nil {
		ccs, err := ReadCcs(c.Config.CcsFile)
		if err != nil {
			c.Logger.Error().Msgf("failed to read %v ccs: %v", c.ComponentName, err)
			return nil, err
		}
		c.Ccs = ccs
	}
	return c.Ccs, nil
}

func (c *CircuitOperations) Verify(vk native_plonk.VerifyingKey, proof native_plonk.Proof, wit witness.Witness, isFront bool) error {
	return PlonkVerify(vk, proof, wit, isFront)
}

func NewConstraintSystem(circuit frontend.Circuit) (constraint.ConstraintSystem, error) {
	field := ecc.BN254.ScalarField()
	ccs, err := frontend.Compile(field, scs.NewBuilder, circuit)
	if err != nil {
		return nil, err
	}
	return ccs, nil
}

func PlonkSetup(ccs constraint.ConstraintSystem, srs *kzg.SRS, srsLagrange *kzg.SRS) (native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {
	pk, vk, err := native_plonk.Setup(ccs, *srs, *srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	return pk, vk, err
}

func PlonkProve(assignment frontend.Circuit, pk native_plonk.ProvingKey, ccs constraint.ConstraintSystem, isFront bool) (native_plonk.Proof, witness.Witness, error) {
	innerField := ecc.BN254.ScalarField()
	outerField := ecc.BN254.ScalarField()
	wit, err := frontend.NewWitness(assignment, innerField)
	if err != nil {
		return nil, nil, err
	}
	var proof native_plonk.Proof
	if isFront {
		proof, err = native_plonk.Prove(ccs, pk, wit)
		if err != nil {
			return nil, nil, err
		}
	} else {
		proof, err = native_plonk.Prove(ccs, pk, wit, plonk.GetNativeProverOptions(outerField, innerField))
		if err != nil {
			return nil, nil, err
		}
	}

	return proof, wit, nil
}

func PlonkVerify(vk native_plonk.VerifyingKey, proof native_plonk.Proof, wit witness.Witness, isFront bool) error {
	innerField := ecc.BN254.ScalarField()
	outerField := ecc.BN254.ScalarField()
	pubWit, err := wit.Public()
	if err != nil {
		return err
	}

	if isFront {
		err = native_plonk.Verify(proof, vk, pubWit)
	} else {
		err = native_plonk.Verify(proof, vk, pubWit, plonk.GetNativeVerifierOptions(outerField, innerField))
	}

	if err != nil {
		return err
	}
	return nil
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

func ExtractFp(ccs constraint.ConstraintSystem, vk native_plonk.VerifyingKey, srsDir string) error {
	log := logger.Logger().With().Str("function", "extractFp").Logger()

	fpExtractor := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccs),
	}
	ccsExtractor, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &fpExtractor)
	if err != nil {
		return err
	}
	size := ccsExtractor.GetNbConstraints() + ccsExtractor.GetNbPublicVariables()

	srs, lsrs, err := ReadSrs(size, srsDir)
	if err != nil {
		return err
	}

	extractFpStart := time.Now()
	pkExtractor, _, err := native_plonk.Setup(ccsExtractor, *srs, *lsrs)
	if err != nil {
		return err
	}

	recursiveVkey, err := plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vk)
	if err != nil {
		return err
	}
	wExt := chainark.FpExtractor[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]{
		Vkey: recursiveVkey,
	}
	witnessExtractor, err := frontend.NewWitness(&wExt, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	_, err = native_plonk.Prove(ccsExtractor, pkExtractor, witnessExtractor)
	if err != nil {
		return err
	}
	log.Debug().Dur("took", time.Since(extractFpStart)).Msg("fp extraction done")

	return nil
}
