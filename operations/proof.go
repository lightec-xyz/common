package operations

import (
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
)

type Proof struct {
	Proof native_plonk.Proof
	Wit   witness.Witness
}
