package operations

import (
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

type Proof struct {
	Proof   plonk.Proof
	Witness witness.Witness
}

type CircuitFile struct {
	Ccs   constraint.ConstraintSystem
	Vkeys []plonk.VerifyingKey
}
