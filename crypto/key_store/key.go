package key_store

import (
	"fmt"
	"strings"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/code.google.com/p/go-uuid/uuid"
	"github.com/eris-ltd/eris-keys/crypto/util"
)

type InvalidCurveErr string

func (err InvalidCurveErr) Error() string {
	return fmt.Sprintf("invalid curve type %v", err)
}

type NoPrivateKeyErr string

func (err NoPrivateKeyErr) Error() string {
	return fmt.Sprintf("Private key is not available or is encrypted")
}

//-----------------------------------------------------------------------------
// set global functions (so we can avoid dependencies in the key store itselF)

type Signer func(*Key, []byte) ([]byte, error)

var signer Signer

func SetSigner(s Signer) {
	if signer != nil {
		return
	}
	signer = s
}

type Pubkeyer func(*Key) ([]byte, error)

var pubkeyer Pubkeyer

func SetPubkeyer(p Pubkeyer) {
	if pubkeyer != nil {
		return
	}
	pubkeyer = p
}

//-----------------------------------------------------------------------------
// main key type

type Key struct {
	Id         uuid.UUID // Version 4 "random" for unique id not derived from key data
	Type       KeyType   // contains curve and addr types
	Address    []byte    // reference id
	PrivateKey []byte    // we don't store pub
}

func (k *Key) Sign(msg []byte) ([]byte, error) {
	return signer(k, msg)
}

func (k *Key) Pubkey() ([]byte, error) {
	return pubkeyer(k)
}

//-----------------------------------------------------------------------------
// key types

type KeyType struct {
	CurveType CurveType
	AddrType  AddrType
}

func (typ KeyType) String() string {
	return fmt.Sprintf("%s,%s", typ.CurveType.String(), typ.AddrType.String())
}

func KeyTypeFromString(s string) (k KeyType, err error) {
	spl := strings.Split(s, ",")
	if len(spl) != 2 {
		return k, fmt.Errorf("KeyType should be (CurveType,AddrType)")
	}

	cType, aType := spl[0], spl[1]
	if k.CurveType, err = CurveTypeFromString(cType); err != nil {
		return
	}
	k.AddrType, err = AddrTypeFromString(aType)
	return
}

//-----------------------------------------------------------------------------
// curve type

type CurveType uint8

func (k CurveType) String() string {
	switch k {
	case CurveTypeSecp256k1:
		return "secp256k1"
	case CurveTypeEd25519:
		return "ed25519"
	default:
		return "unknown"
	}
}

func CurveTypeFromString(s string) (CurveType, error) {
	switch s {
	case "secp256k1":
		return CurveTypeSecp256k1, nil
	case "ed25519":
		return CurveTypeEd25519, nil
	default:
		var k CurveType
		return k, InvalidCurveErr(s)
	}
}

const (
	CurveTypeSecp256k1 CurveType = iota
	CurveTypeEd25519
)

//-----------------------------------------------------------------------------
// address type

type AddrType uint8

func (a AddrType) String() string {
	switch a {
	case AddrTypeRipemd160:
		return "ripemd160"
	case AddrTypeRipemd160Sha256:
		return "ripemd160sha256"
	case AddrTypeSha3:
		return "sha3"
	default:
		return "unknown"
	}
}

func AddrTypeFromString(s string) (AddrType, error) {
	switch s {
	case "ripemd160":
		return AddrTypeRipemd160, nil
	case "ripemd160sha256":
		return AddrTypeRipemd160Sha256, nil
	case "sha3":
		return AddrTypeSha3, nil
	default:
		var a AddrType
		return a, fmt.Errorf("unknown addr type %s", s)
	}
}

const (
	AddrTypeRipemd160 AddrType = iota
	AddrTypeRipemd160Sha256
	AddrTypeSha3
)

func AddressFromPub(addrType AddrType, pub []byte) (addr []byte) {
	switch addrType {
	case AddrTypeRipemd160:
		// let tendermint/binary handle because
		// it encodes the type byte ...
	case AddrTypeRipemd160Sha256:
		addr = util.Ripemd160(util.Sha256(pub))
	case AddrTypeSha3:
		addr = util.Sha3(pub[1:])[12:]
	}
	return
}
