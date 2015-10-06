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
	"fmt"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/code.google.com/p/go-uuid/uuid"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/ed25519"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/tendermint/account"
	. "github.com/eris-ltd/eris-keys/crypto/key_store"
	"github.com/eris-ltd/eris-keys/crypto/randentropy"
	"github.com/eris-ltd/eris-keys/crypto/secp256k1"
)

// on init we set the key_store functions
func init() {
	SetGenerator(GenerateNewKeyDefault)
	SetSigner(Signer(Sign))
	SetPubkeyer(Pubkeyer(Pubkey))
}

func GenerateNewKeyDefault(ks KeyStore, typ KeyType, auth string) (key *Key, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("GenerateNewKey error: %v", r)
		}
	}()
	key, err = NewKey(typ)
	if err != nil {
		return nil, err
	}
	err = ks.StoreKey(key, auth)
	return key, err
}

//-----------------------------------------------------------------------------
// main key struct and functions (sign, pubkey, verify)

func NewKey(typ KeyType) (*Key, error) {
	switch typ.CurveType {
	case CurveTypeSecp256k1:
		return newKeySecp256k1(typ.AddrType), nil
	case CurveTypeEd25519:
		return newKeyEd25519(typ.AddrType), nil
	default:
		return nil, fmt.Errorf("Unknown curve type: %v", typ.CurveType)
	}
}

func NewKeyFromPriv(typ KeyType, priv []byte) (*Key, error) {
	switch typ.CurveType {
	case CurveTypeSecp256k1:
		return keyFromPrivSecp256k1(typ.AddrType, priv)
	case CurveTypeEd25519:
		return keyFromPrivEd25519(typ.AddrType, priv)
	default:
		return nil, fmt.Errorf("Unknown curve type: %v", typ.CurveType)
	}
}

func Sign(k *Key, hash []byte) ([]byte, error) {
	switch k.Type.CurveType {
	case CurveTypeSecp256k1:
		return signSecp256k1(k, hash)
	case CurveTypeEd25519:
		return signEd25519(k, hash)
	}
	return nil, InvalidCurveErr(k.Type.CurveType)
}

func Pubkey(k *Key) ([]byte, error) {
	switch k.Type.CurveType {
	case CurveTypeSecp256k1:
		return pubKeySecp256k1(k)
	case CurveTypeEd25519:
		return pubKeyEd25519(k)
	}
	return nil, InvalidCurveErr(k.Type.CurveType)
}

func Verify(curveType CurveType, hash, sig, pub []byte) (bool, error) {
	switch curveType {
	case CurveTypeSecp256k1:
		return verifySigSecp256k1(hash, sig, pub)
	case CurveTypeEd25519:
		return verifySigEd25519(hash, sig, pub)
	}
	return false, InvalidCurveErr(curveType)
}

//-----------------------------------------------------------------------------
// main utility functions for each key type (new, pub, sign, verify)
// TODO: run all sorts of length and validity checks

func newKeySecp256k1(addrType AddrType) *Key {
	pub, priv := secp256k1.GenerateKeyPair()
	return &Key{
		Id:         uuid.NewRandom(),
		Type:       KeyType{CurveTypeSecp256k1, addrType},
		Address:    AddressFromPub(addrType, pub),
		PrivateKey: priv,
	}
}

func newKeyEd25519(addrType AddrType) *Key {
	randBytes := randentropy.GetEntropyMixed(32)
	key, _ := keyFromPrivEd25519(addrType, randBytes)
	return key
}

func keyFromPrivSecp256k1(addrType AddrType, priv []byte) (*Key, error) {
	pub, err := secp256k1.GeneratePubKey(priv)
	if err != nil {
		return nil, err
	}
	return &Key{
		Id:         uuid.NewRandom(),
		Type:       KeyType{CurveTypeSecp256k1, addrType},
		Address:    AddressFromPub(addrType, pub),
		PrivateKey: priv,
	}, nil
}

func keyFromPrivEd25519(addrType AddrType, priv []byte) (*Key, error) {
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], priv)
	pubKeyBytes := ed25519.MakePublicKey(privKeyBytes)
	pubKey := account.PubKeyEd25519(*pubKeyBytes)
	return &Key{
		Id:         uuid.NewRandom(),
		Type:       KeyType{CurveTypeEd25519, addrType},
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
	var privKey account.PrivKeyEd25519
	copy(privKey[:], priv)
	sig := privKey.Sign(hash)
	sigB := sig.(account.SignatureEd25519)
	return sigB[:], nil
}

func verifySigSecp256k1(hash, sig, pubOG []byte) (bool, error) {
	pub, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return false, err
	}

	if bytes.Compare(pub, pubOG) != 0 {
		return false, fmt.Errorf("Recovered pub key does not match. Got %X, expected %X", pub, pubOG)
	}

	// TODO: validate recovered pub!

	return true, nil
}

func verifySigEd25519(hash, sig, pub []byte) (bool, error) {
	pubKeyBytes := new([32]byte)
	copy(pubKeyBytes[:], pub)
	sigBytes := new([64]byte)
	copy(sigBytes[:], sig)
	res := ed25519.Verify(pubKeyBytes, hash, sigBytes)
	return res, nil
}
