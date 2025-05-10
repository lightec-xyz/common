package operations

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"path/filepath"
	"testing"
)

var (
	cubicCcsFile = "cubic.ccs"
	cubicPkFile  = "cubic.pk"
	cubicVkFile  = "cubic.vk"
	toxicValue   = []byte{05, 06, 07} //seed for srs
)

// Circuit defines a simple circuit
// x**3 + 2*x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + 2*x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	xCubic := api.Mul(circuit.X, circuit.X, circuit.X)
	doubleX := api.Mul(2, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(xCubic, doubleX, 5))
	return nil
}

func NewCubicCircuit() (frontend.Circuit, error) {
	var circuit CubicCircuit
	return &circuit, nil
}

func NewCubicCircuitAssignment(x, y frontend.Variable) (frontend.Circuit, error) {
	assignment := CubicCircuit{
		X: x,
		Y: y,
	}
	return &assignment, nil
}
func NewCubicConfig(circuitDir string, srsDir string, dataDir string) *Config {
	return &Config{
		CcsFile:    filepath.Join(circuitDir, cubicCcsFile),
		VkFile:     filepath.Join(circuitDir, cubicVkFile),
		PkFile:     filepath.Join(circuitDir, cubicPkFile),
		CircuitDir: circuitDir,
		SrsDir:     srsDir,
		DataDir:    dataDir,
	}
}

type Cubic struct {
	CircuitOperations
}

func NewCubic(cfg *Config) *Cubic {
	return &Cubic{
		CircuitOperations{
			Config:        cfg,
			ComponentName: "cubic",
		},
	}
}

func (c *Cubic) Load() error {
	return c.LoadCcsPkVk()
}

func (c *Cubic) Prove(x, y int) {
	assignment, _ := NewCubicCircuitAssignment(x, y)
	c.ProveWithAssignment(assignment, true)

}

func SetupCubicCircuit(dir string) error {
	circuit, _ := NewCubicCircuit()
	ccs, err := NewConstraintSystem(circuit)
	if err != nil {
		return err
	}
	fmt.Printf("nbConstraints:%v, nbPublicWitness:%v, nbSecretWitness:%v, nbInternalVariables:%v\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), ccs.GetNbSecretVariables(), ccs.GetNbInternalVariables())

	srs, lsrs, err := unsafekzg.NewSRS(ccs, unsafekzg.WithToxicSeed(toxicValue))
	if err != nil {
		return err
	}

	pk, vk, err := PlonkSetup(ccs, &srs, &lsrs)
	if err != nil {
		return err
	}

	err = WriteCcs(ccs, filepath.Join(dir, cubicCcsFile))
	if err != nil {
		return err
	}
	err = WritePk(pk, filepath.Join(dir, cubicPkFile))
	if err != nil {
		return err
	}
	err = WriteVk(vk, filepath.Join(dir, cubicVkFile))
	if err != nil {
		return err
	}
	return nil
}
func Test_LRUCircuits(t *testing.T) {
	tmpDir := t.TempDir()

	err := SetupCubicCircuit(tmpDir)
	assert.NoError(t, err)

	InitLru(3)
	for i := 0; i < 3; i++ {
		x := int(rand.Int31n(100))
		y := x*x*x + 2*x + 5
		config := NewCubicConfig(tmpDir, "", tmpDir)
		instance := NewCubic(config)
		instance.Load()
		instance.Prove(x, y)
	}
}
