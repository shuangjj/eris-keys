package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/eris-ltd/epm-go/utils"
	"github.com/eris-ltd/eris-keys/crypto"
	"github.com/tendermint/tendermint/account"
	_ "github.com/tendermint/tendermint/binary"
)

var (
	DIR   = utils.Scratch
	AUTH  = ""
	TYPES = []string{"secp256k1", "ed25519"}
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
	for _, typ := range TYPES {
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
	for _, typ := range TYPES {
		testSignAndVerify(t, typ)
	}
}

//--------------------------------------------------------------------------------

func toHex(b []byte) string {
	return fmt.Sprintf("%x", b)
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
