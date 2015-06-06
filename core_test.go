package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/epm-go/utils"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/tendermint/account"
	_ "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/tendermint/binary"
	"github.com/eris-ltd/eris-keys/crypto"
)

var (
	DIR        = utils.Scratch
	AUTH       = ""
	KEY_TYPES  = []string{"secp256k1", "ed25519"}
	HASH_TYPES = []string{"sha256", "ripemd160"}
)

func testKeygenAndPub(t *testing.T, typ string) {
	addr, err := coreKeygen(DIR, AUTH, typ)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := corePub(DIR, AUTH, toHex(addr))
	if err != nil {
		t.Fatal(err)
	}

	if err := checkAddrFromPub(typ, pub, addr); err != nil {
		t.Fatal(err)
	}

}

func TestKeygenAndPub(t *testing.T) {
	for _, typ := range KEY_TYPES {
		testKeygenAndPub(t, typ)
	}
}

func testSignAndVerify(t *testing.T, typ string) {
	addr, err := coreKeygen(DIR, AUTH, typ)
	if err != nil {
		t.Fatal(err)
	}

	hash := crypto.Sha3([]byte("the hash of something!"))

	sig, err := coreSign(DIR, AUTH, toHex(hash), toHex(addr))
	if err != nil {
		t.Fatal(err)
	}

	res, err := coreVerify(DIR, AUTH, toHex(addr), toHex(hash), toHex(sig))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Sig: %X, %v\n", sig, res)
}

func TestSignAndVerify(t *testing.T) {
	for _, typ := range KEY_TYPES {
		testSignAndVerify(t, typ)
	}
}

func testHash(t *testing.T, typ string) {
	hData := hashData[typ]
	data, expected := hData.data, hData.expected
	hash, err := coreHash(typ, data)
	if err != nil {
		t.Fatal(err)
	}

	if toHex(hash) != expected {
		t.Fatalf("Hash error for %s. Got %s, expected %s", typ, toHex(hash), expected)
	}

}

type hashInfo struct {
	data     string
	expected string
}

var hashData = map[string]hashInfo{
	"sha256":    hashInfo{"hi", "8F434346648F6B96DF89DDA901C5176B10A6D83961DD3C1AC88B59B2DC327AA4"},
	"ripemd160": hashInfo{"hi", "242485AB6BFD3502BCB3442EA2E211687B8E4D89"},
}

func TestHash(t *testing.T) {
	for _, typ := range HASH_TYPES {
		testHash(t, typ)
	}
}

//--------------------------------------------------------------------------------

func toHex(b []byte) string {
	return fmt.Sprintf("%X", b)
}

func checkAddrFromPub(typ string, pub, addr []byte) error {
	var addr2 []byte
	switch typ {
	case "secp256k1":
		addr2 = crypto.Sha3(pub[1:])[12:]
	case "ed25519":
		// XXX: something weird here. I have seen this oscillate!
		// addr2 = binary.BinaryRipemd160(pub)
		addr2 = account.PubKeyEd25519(pub).Address()
	}
	if bytes.Compare(addr, addr2) != 0 {
		return fmt.Errorf("Keygen addr doesn't match pub. Got %X, expected %X", addr2, addr)
	}
	return nil
}
