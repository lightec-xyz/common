package operations

import (
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
)

type Proof struct {
	Proof   native_plonk.Proof
	Witness witness.Witness
}
