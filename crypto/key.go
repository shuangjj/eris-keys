/*
	This file is part of go-ethereum

	go-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	go-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with go-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * @authors
 * 	Gustav Simonsson <gustav.simonsson@gmail.com>
 *	Ethan Buchman <ethan@erisindustries.com> (adapt for ed25519 keys also)
 * @date 2015
 *
 */

package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"code.google.com/p/go-uuid/uuid"
	"github.com/eris-ltd/eris-keys/crypto/randentropy"
	"github.com/eris-ltd/eris-keys/crypto/secp256k1"
	"github.com/tendermint/ed25519"
	"github.com/tendermint/tendermint/account"
)

//-----------------------------------------------------------------------------
// key type

type KeyType uint8

func (k KeyType) String() string {
	switch k {
	case KeyTypeSecp256k1:
		return "secp256k1"
	case KeyTypeEd25519:
		return "ed25519"
	default:
		return "unknown"
	}
}

func KeyTypeFromString(s string) (KeyType, error) {
	switch s {
	case "secp256k1":
		return KeyTypeSecp256k1, nil
	case "ed25519":
		return KeyTypeEd25519, nil
	default:
		var k KeyType
		return k, fmt.Errorf("unknown key type %s", s)
	}
}

const (
	KeyTypeSecp256k1 KeyType = iota
	KeyTypeEd25519
)

//-----------------------------------------------------------------------------
// main key struct and functions (sign, pubkey, verify)

type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// key may be secp256k1 or ed25519 or potentially others
	Type KeyType
	// to simplify lookups we also store the address
	Address []byte
	// we only store privkey as pubkey/address can be derived from it
	// privkey in this struct is always in plaintext
	PrivateKey []byte
}

func NewKey(typ KeyType) (*Key, error) {
	switch typ {
	case KeyTypeSecp256k1:
		return newKeySecp256k1(), nil
	case KeyTypeEd25519:
		return newKeyEd25519(), nil
	default:
		return nil, fmt.Errorf("Unknown key type: %v", typ)
	}
}

func NewKeyFromPriv(typ KeyType, priv []byte) (*Key, error) {
	switch typ {
	case KeyTypeSecp256k1:
		return keyFromPrivSecp256k1(priv)
	case KeyTypeEd25519:
		return keyFromPrivEd25519(priv)
	default:
		return nil, fmt.Errorf("Unknown key type: %v", typ)
	}
}

func (k *Key) Sign(hash []byte) ([]byte, error) {
	switch k.Type {
	case KeyTypeSecp256k1:
		return signSecp256k1(k, hash)
	case KeyTypeEd25519:
		return signEd25519(k, hash)
	}
	return nil, fmt.Errorf("invalid key type %v", k.Type)

}

func (k *Key) Pubkey() ([]byte, error) {
	switch k.Type {
	case KeyTypeSecp256k1:
		return pubKeySecp256k1(k)
	case KeyTypeEd25519:
		return pubKeyEd25519(k)
	}
	return nil, fmt.Errorf("invalid key type %v", k.Type)
}

func (k *Key) Verify(hash, sig []byte) (bool, error) {
	switch k.Type {
	case KeyTypeSecp256k1:
		return verifySigSecp256k1(k, hash, sig)
	case KeyTypeEd25519:
		return verifySigEd25519(k, hash, sig)
	}
	return false, fmt.Errorf("invalid key type %v", k.Type)
}

//-----------------------------------------------------------------------------
// json encodings

// addresses should be hex encoded

type plainKeyJSON struct {
	Id         []byte
	Type       string
	Address    string
	PrivateKey []byte
}

type cipherJSON struct {
	Salt       []byte
	Nonce      []byte
	CipherText []byte
}

type encryptedKeyJSON struct {
	Id      []byte
	Type    string
	Address string
	Crypto  cipherJSON
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	jStruct := plainKeyJSON{
		k.Id,
		k.Type.String(),
		fmt.Sprintf("%x", k.Address),
		k.PrivateKey,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}

	u := new(uuid.UUID)
	*u = keyJSON.Id
	k.Id = *u
	k.Address, err = hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	k.PrivateKey = keyJSON.PrivateKey
	k.Type, err = KeyTypeFromString(keyJSON.Type)

	return err
}

//-----------------------------------------------------------------------------
// main utility functions for each key type (new, pub, sign, verify)
// TODO: run all sorts of length and validity checks

func newKeySecp256k1() *Key {
	pub, priv := secp256k1.GenerateKeyPair()
	return &Key{
		Id:         uuid.NewRandom(),
		Type:       KeyTypeSecp256k1,
		Address:    Sha3(pub[1:])[12:],
		PrivateKey: priv,
	}
}

func newKeyEd25519() *Key {
	randBytes := randentropy.GetEntropyMixed(32)
	key, _ := keyFromPrivEd25519(randBytes)
	return key
}

func keyFromPrivSecp256k1(priv []byte) (*Key, error) {
	pub, err := secp256k1.GeneratePubKey(priv)
	if err != nil {
		return nil, err
	}
	return &Key{
		Id:         uuid.NewRandom(),
		Type:       KeyTypeSecp256k1,
		Address:    Sha3(pub[1:])[12:],
		PrivateKey: priv,
	}, nil
}

func keyFromPrivEd25519(priv []byte) (*Key, error) {
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], priv)
	pubKeyBytes := ed25519.MakePublicKey(privKeyBytes)
	pubKey := account.PubKeyEd25519(pubKeyBytes[:])
	return &Key{
		Id:         uuid.NewRandom(),
		Type:       KeyTypeEd25519,
		Address:    pubKey.Address(),
		PrivateKey: privKeyBytes[:],
	}, nil
}

func pubKeySecp256k1(k *Key) ([]byte, error) {
	return secp256k1.GeneratePubKey(k.PrivateKey)
}

func pubKeyEd25519(k *Key) ([]byte, error) {
	priv := k.PrivateKey
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], priv)
	pubKeyBytes := ed25519.MakePublicKey(privKeyBytes)
	return pubKeyBytes[:], nil
}

func signSecp256k1(k *Key, hash []byte) ([]byte, error) {
	return secp256k1.Sign(hash, k.PrivateKey)
}

func signEd25519(k *Key, hash []byte) ([]byte, error) {
	priv := k.PrivateKey
	var privKeyBytes [64]byte
	copy(privKeyBytes[:32], priv)
	privKey := account.PrivKeyEd25519(privKeyBytes[:])
	sig := privKey.Sign(hash)
	sigB := []byte(sig.(account.SignatureEd25519))
	return sigB, nil
}

func verifySigSecp256k1(k *Key, hash, sig []byte) (bool, error) {
	pub, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return false, err
	}

	pubOG, err := k.Pubkey()
	if err != nil {
		return false, err
	}

	if bytes.Compare(pub, pubOG) != 0 {
		return false, fmt.Errorf("Recovered pub key does not match. Got %X, expected %X", pub, pubOG)
	}

	// TODO: validate recovered pub!

	return true, nil
}

func verifySigEd25519(k *Key, hash, sig []byte) (bool, error) {
	pub, err := k.Pubkey()
	if err != nil {
		return false, err
	}
	pubKeyBytes := new([32]byte)
	copy(pubKeyBytes[:], pub)
	sigBytes := new([64]byte)
	copy(sigBytes[:], sig)
	res := ed25519.Verify(pubKeyBytes, hash, sigBytes)
	return res, nil
}
