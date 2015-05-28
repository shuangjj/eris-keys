package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"path/filepath"

	"code.google.com/p/go.crypto/ripemd160"
	"github.com/eris-ltd/eris-keys/crypto"
)

func newKeyStore(dir, auth string) (keyStore crypto.KeyStore, err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		keyStore = crypto.NewKeyStorePassphrase(dir)
	} else {
		keyStore = crypto.NewKeyStorePlain(dir)

	}
	return
}

func coreKeygen(dir, auth, keyType string) ([]byte, error) {
	keyStore, err := newKeyStore(dir, auth)
	if err != nil {
		return nil, err
	}

	var key *crypto.Key
	switch keyType {
	case "secp256k1", "ethereum", "thelonious":
		// TODO: deal with bitcoin (different address gen mechanism)
		key, err = keyStore.GenerateNewKey(crypto.KeyTypeSecp256k1, auth)
	case "ed25519", "tendermint":
		key, err = keyStore.GenerateNewKey(crypto.KeyTypeEd25519, auth)
	default:
		err = fmt.Errorf("unknown key type: %s", keyType)
	}
	//TODO: oveerwrite priv, auth
	if err != nil {
		return nil, fmt.Errorf("error generating key %s %s", keyType, err)
	}
	return key.Address, nil
}

func coreSign(dir, auth, hash, addr string) ([]byte, error) {
	hashB, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("hash is invalid hex: %s", err.Error())
	}
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}
	keyStore, err := newKeyStore(dir, auth)
	if err != nil {
		return nil, err
	}

	key, err := keyStore.GetKey(addrB, auth)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key for %x: %v", addrB, err)
	}
	sig, err := key.Sign(hashB)
	if err != nil {
		return nil, fmt.Errorf("error signing %x using %x: %v", hashB, addrB, err)
	}
	return sig, nil
}

func coreVerify(dir, auth, addr, hash, sig string) (result bool, err error) {
	hashB, err := hex.DecodeString(hash)
	if err != nil {
		return result, fmt.Errorf("hash is invalid hex: %s", err.Error())
	}
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return result, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}
	sigB, err := hex.DecodeString(sig)
	if err != nil {
		return result, fmt.Errorf("sig is invalid hex: %s", err.Error())
	}
	keyStore, err := newKeyStore(dir, auth)
	if err != nil {
		return result, fmt.Errorf("error opening keyStore %s", err.Error())
	}

	key, err := keyStore.GetKey(addrB, auth)
	if err != nil {
		return result, fmt.Errorf("error retrieving key for %x: %v", addrB, err)
	}

	result, err = key.Verify(hashB, sigB)
	if err != nil {
		return result, fmt.Errorf("error verifying signature %x for address %x: %v", sigB, addrB, err)
	}

	return
}

func corePub(dir, auth, addr string) ([]byte, error) {
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}

	keyStore, err := newKeyStore(dir, auth)
	if err != nil {
		return nil, fmt.Errorf("error opening keyStore %s", err.Error())
	}

	key, err := keyStore.GetKey(addrB, auth)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key for %x: %v", addrB, err)
	}
	pub, err := key.Pubkey()
	if err != nil {
		return nil, fmt.Errorf("error retrieving pub key for %x: %v", addrB, err)
	}
	return pub, nil
}

func coreHash(typ, data string) ([]byte, error) {
	var hasher hash.Hash
	switch typ {
	case "ripemd160":
		hasher = ripemd160.New()
	case "sha256":
		hasher = sha256.New()
	// case "sha3":
	default:
		return nil, fmt.Errorf("Unknown hash type %s", typ)
	}
	io.WriteString(hasher, data)
	return hasher.Sum(nil), nil
}
