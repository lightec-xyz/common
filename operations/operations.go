package operations

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion/plonk"
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

func (c *CircuitOperations) SetupWithCircuit(circuit frontend.Circuit) error {
	log := logger.Logger().With().Str("component", c.ComponentName).Logger()

	ccs, err := NewConstraintSystem(circuit)
	if err != nil {
		log.Error().Msgf("failed to new %v constraint system: %v", c.ComponentName, err)
		return err
	}

	srs, lsrs, err := ReadSrs(ccs.GetNbConstraints()+ccs.GetNbPublicVariables(), c.Config.SrsDir)
	if err != nil {
		log.Error().Msgf("failed to read srs: %v", err)
		return err
	}

	pk, vk, err := PlonkSetup(ccs, srs, lsrs)
	if err != nil {
		log.Error().Msgf("failed to init %v pk vk: %v", c.ComponentName, err)
		return err
	}

	c.Ccs = ccs
	c.ProvingKey = pk
	c.VerifyingKey = vk
	c.Logger = &log

	return nil
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
	proof, wit, err := PlonkProve(c.Ccs, c.ProvingKey, assignment, isFront)
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
		Proof:   proof,
		Witness: wit,
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

func PlonkProve(ccs constraint.ConstraintSystem, pk native_plonk.ProvingKey, assignment frontend.Circuit, isFront bool) (native_plonk.Proof, witness.Witness, error) {
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
