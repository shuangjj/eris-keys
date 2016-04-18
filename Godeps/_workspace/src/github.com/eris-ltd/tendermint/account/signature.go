package account

import (
	"fmt"

	. "github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/shuangjj/tendermint/common"
	"github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/shuangjj/tendermint/wire"
)

// Signature is a part of Txs and consensus Votes.
type Signature interface {
	IsZero() bool
	String() string
}

// Types of Signature implementations
const (
	SignatureTypeEd25519 = byte(0x01)
)

// for wire.readReflect
var _ = wire.RegisterInterface(
	struct{ Signature }{},
	wire.ConcreteType{SignatureEd25519{}, SignatureTypeEd25519},
)

//-------------------------------------

// Implements Signature
type SignatureEd25519 [64]byte

func (sig SignatureEd25519) IsZero() bool { return len(sig) == 0 }

func (sig SignatureEd25519) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }
