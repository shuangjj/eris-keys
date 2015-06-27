package commands

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/eris-ltd/eris-keys/crypto"
)

// start the server
func init() {
	failedCh := make(chan error)
	go func() {
		err := ListenAndServe(DefaultHost, TestPort)
		failedCh <- err
	}()
	tick := time.NewTicker(time.Second)
	select {
	case err := <-failedCh:
		fmt.Println(err)
		os.Exit(1)
	case <-tick.C:
	}
}

// tests are identical to core_test.go but through the http calls instead of the core functions

func testServerKeygenAndPub(t *testing.T, typ string) {
	req, _ := http.NewRequest("GET", TestAddr+"/gen", nil)
	req.Header.Add("type", typ)
	addr, errS, err := requestResponse(req)
	checkErrs(t, errS, err)

	req, _ = http.NewRequest("GET", TestAddr+"/pub", nil)
	req.Header.Add("addr", addr)
	pub, errS, err := requestResponse(req)
	checkErrs(t, errS, err)

	pubB, _ := hex.DecodeString(pub)
	addrB, _ := hex.DecodeString(addr)
	if err := checkAddrFromPub(typ, pubB, addrB); err != nil {
		t.Fatal(err)
	}
}

func TestServerKeygenAndPub(t *testing.T) {
	for _, typ := range KEY_TYPES {
		testServerKeygenAndPub(t, typ)
	}
}

func testServerSignAndVerify(t *testing.T, typ string) {
	req, _ := http.NewRequest("GET", TestAddr+"/gen", nil)
	req.Header.Add("type", typ)
	addr, errS, err := requestResponse(req)
	checkErrs(t, errS, err)

	hash := crypto.Sha3([]byte("the hash of something!"))

	req, _ = http.NewRequest("GET", TestAddr+"/sign", nil)
	req.Header.Add("hash", toHex(hash))
	req.Header.Add("addr", addr)
	sig, errS, err := requestResponse(req)
	checkErrs(t, errS, err)

	req, _ = http.NewRequest("GET", TestAddr+"/verify", nil)
	req.Header.Add("hash", toHex(hash))
	req.Header.Add("addr", addr)
	req.Header.Add("sig", sig)
	res, errS, err := requestResponse(req)
	checkErrs(t, errS, err)

	if res != "true" {
		t.Fatalf("Signature failed to verify. Sig %s, Hash %s, Addr %s", sig, toHex(hash), addr)
	}

	fmt.Printf("Sig: %X, %v\n", sig, res)
}

func TestServerSignAndVerify(t *testing.T) {
	for _, typ := range KEY_TYPES {
		testServerSignAndVerify(t, typ)
	}
}

func testServerHash(t *testing.T, typ string) {
	hData := hashData[typ]
	data, expected := hData.data, hData.expected

	req, _ := http.NewRequest("GET", TestAddr+"/hash", nil)
	req.Header.Add("type", typ)
	req.Header.Add("data", data)
	hash, errS, err := requestResponse(req)
	checkErrs(t, errS, err)

	if hash != expected {
		t.Fatalf("Hash error for %s. Got %s, expected %s", typ, hash, expected)
	}
}

func TestServerHash(t *testing.T) {
	for _, typ := range HASH_TYPES {
		testServerHash(t, typ)
	}
}

//---------------------------------------------------------------------------------

func checkErrs(t *testing.T, errS string, err error) {
	if err != nil {
		t.Fatal(err)
	}
	if errS != "" {
		t.Fatal(errS)
	}
}
