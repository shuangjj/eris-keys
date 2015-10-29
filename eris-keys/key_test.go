package keys

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	kstore "github.com/eris-ltd/mint-client/Godeps/_workspace/src/github.com/eris-ltd/eris-keys/crypto/key_store"
	"github.com/eris-ltd/mint-client/Godeps/_workspace/src/github.com/tendermint/tendermint/wire"
)

var keyPath string

func init() {
	DefaultKeyStore = path.Join(os.TempDir(), "data")
	keyPath = path.Join(DefaultKeyStore, addr)
}

var addr = "098E260AD99FFAE17A02E0F3692C7A493B122274"

var erisKey = `{"Id":"VeiTBAZdQGu5Z2gXvuS7sQ==","Type":"ed25519,ripemd160","Address":"098E260AD99FFAE17A02E0F3692C7A493B122274","PrivateKey":"jQkNeMfYdBw4FNcivzSGqTfvlZX9ZpDC0ma+vS7d1zAzacgZwmXVe5MD8RJmbQ/9bCLuCN6KAnf07rfq2ApoBw=="}`

var mintKey = `{"address":"098E260AD99FFAE17A02E0F3692C7A493B122274","pub_key":[1,"3369C819C265D57B9303F112666D0FFD6C22EE08DE8A0277F4EEB7EAD80A6807"],"priv_key":[1,"8D090D78C7D8741C3814D722BF3486A937EF9595FD6690C2D266BEBD2EDDD7303369C819C265D57B9303F112666D0FFD6C22EE08DE8A0277F4EEB7EAD80A6807"],"last_height":0,"last_round":0,"last_step":0}`

func TestErisToMint(t *testing.T) {
	keyPath := path.Join(DefaultKeyStore, addr)
	if err := os.MkdirAll(keyPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(path.Join(keyPath, addr), []byte(erisKey), 0600); err != nil {
		t.Fatal(err)
	}

	addrBytes, _ := hex.DecodeString(addr)

	pv, err := coreConvertErisKeyToPrivValidator(addrBytes)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%v\n", string(wire.JSONBytes(pv)))
	fmt.Printf("%v\n", mintKey)

	if string(wire.JSONBytes(pv)) != mintKey {
		t.Fatalf("got \n%s \n\n expected \n %s\n", string(wire.JSONBytes(pv)), mintKey)
	}

	os.RemoveAll(DefaultKeyStore)
}

func TestMintToEris(t *testing.T) {
	if err := os.MkdirAll(DefaultKeyStore, 0700); err != nil {
		t.Fatal(err)
	}
	key := new(kstore.Key)
	if err := key.UnmarshalJSON([]byte(erisKey)); err != nil {
		t.Fatal(err)
	}

	k, err := coreConvertPrivValidatorToErisKey([]byte(mintKey))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = ioutil.ReadFile(path.Join(keyPath, addr)); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(k.PrivateKey, key.PrivateKey) {
		t.Fatalf("got \n%s \n\n expected \n %s\n", k, key)
	}

	os.RemoveAll(DefaultKeyStore)
}
