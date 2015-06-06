package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"path/filepath"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/code.google.com/p/go.crypto/ripemd160"
	"github.com/eris-ltd/eris-keys/crypto"
)

// TODO: overwrite all mem buffers/registers?

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

func coreImport(dir, auth, keyType, keyHex string) ([]byte, error) {
	keyStore, err := newKeyStore(dir, auth)
	if err != nil {
		return nil, err
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("private key is invalid hex: %v", err)
	}

	keyT, err := crypto.KeyTypeFromString(keyType)
	if err != nil {
		return nil, err
	}
	key, err := crypto.NewKeyFromPriv(keyT, keyBytes)
	if err != nil {
		return nil, err
	}

	// store the new key
	if err = keyStore.StoreKey(key, auth); err != nil {
		return nil, err
	}

	return key.Address, nil
}

func coreKeygen(dir, auth, keyType string) ([]byte, error) {
	keyStore, err := newKeyStore(dir, auth)
	if err != nil {
		return nil, err
	}

	var key *crypto.Key
	keyT, err := crypto.KeyTypeFromString(keyType)
	if err != nil {
		return nil, err
	}
	key, err = keyStore.GenerateNewKey(keyT, auth)
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
