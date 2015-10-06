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
 * @date 2015
 *
 */

/*

This key store behaves as KeyStorePlain with the difference that
the private key is encrypted and on disk uses another JSON encoding.

Cryptography:

1. Encryption key is scrypt derived key from user passphrase. Scrypt parameters
   (work factors) [1][2] are defined as constants below.
2. Scrypt salt is 32 random bytes from CSPRNG. It is appended to ciphertext.
3. Checksum is SHA3 of the private key bytes.
4. Plaintext is concatenation of private key bytes and checksum.
5. Encryption algo is AES 256 CBC [3][4]
6. CBC IV is 16 random bytes from CSPRNG. It is appended to ciphertext.
7. Plaintext padding is PKCS #7 [5][6]

Encoding:

1. On disk, ciphertext, salt and IV are encoded in a nested JSON object.
   cat a key file to see the structure.
2. byte arrays are base64 JSON strings.
3. The EC private key bytes are in uncompressed form [7].
   They are a big-endian byte slice of the absolute value of D [8][9].
4. The checksum is the last 32 bytes of the plaintext byte array and the
   private key is the preceeding bytes.

References:

1. http://www.tarsnap.com/scrypt/scrypt-slides.pdf
2. http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors
3. http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
4. http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29
5. https://leanpub.com/gocrypto/read#leanpub-auto-block-cipher-modes
6. http://tools.ietf.org/html/rfc2315
7. http://bitcoin.stackexchange.com/questions/3059/what-is-a-compressed-bitcoin-key
8. http://golang.org/pkg/crypto/ecdsa/#PrivateKey
9. https://golang.org/pkg/math/big/#Int.Bytes

*/

/*
	Modifications:
		- Ethan Buchman <ethan@erisindustries.com>

	encryption has been modified to use GCM instead of CBC as it
	provides authenticated encryption, rather than managing the
	additional checksum ourselves. The CBC IV is replaced by a Nonce
	that may only be used once ever per key
*/

package key_store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/code.google.com/p/go-uuid/uuid"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/golang.org/x/crypto/scrypt" // 2^18 / 8 / 1 uses 256MB memory and approx 1s CPU time on a modern CPU.
	"github.com/eris-ltd/eris-keys/crypto/randentropy"
	"github.com/eris-ltd/eris-keys/crypto/util"
)

const (
	version = 3
)

const (
	scryptN     = 1 << 18
	scryptr     = 8
	scryptp     = 1
	scryptdkLen = 32
)

type keyStorePassphrase struct {
	keysDirPath string
}

func NewKeyStorePassphrase(path string) KeyStore {
	return &keyStorePassphrase{path}
}

func (ks keyStorePassphrase) GenerateNewKey(typ KeyType, auth string) (key *Key, err error) {
	return gen(ks, typ, auth)
}

func (ks keyStorePassphrase) GetKey(keyAddr []byte, auth string) (key *Key, err error) {
	key, err = DecryptKey(ks, keyAddr, auth)
	if err != nil {
		return nil, err
	}
	return key, err
}

func (ks keyStorePassphrase) GetAllAddresses() (addresses [][]byte, err error) {
	return GetAllAddresses(ks.keysDirPath)
}

func (ks keyStorePassphrase) StoreKey(key *Key, auth string) (err error) {
	authArray := []byte(auth)
	salt := randentropy.GetEntropyCSPRNG(32)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptr, scryptp, scryptdkLen)
	if err != nil {
		return err
	}

	encryptKey := derivedKey[:16]
	keyBytes := key.PrivateKey
	toEncrypt := util.PKCS7Pad(keyBytes)

	AES256Block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(AES256Block)
	if err != nil {
		return err
	}

	// XXX: a GCM nonce may only be used once per key ever!
	nonce := randentropy.GetEntropyCSPRNG(gcm.NonceSize())

	// (dst, nonce, plaintext, extradata)
	cipherText := gcm.Seal(nil, nonce, toEncrypt, nil)

	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = scryptN
	scryptParamsJSON["r"] = scryptr
	scryptParamsJSON["p"] = scryptp
	scryptParamsJSON["dklen"] = scryptdkLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		Nonce: hex.EncodeToString(nonce),
	}

	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-gcm",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          "scrypt",
		KDFParams:    scryptParamsJSON,
	}
	encryptedKeyJSONV3 := encryptedKeyJSONv3{
		Address: hex.EncodeToString(key.Address[:]),
		Crypto:  cryptoStruct,
		Id:      key.Id.String(),
		Type:    key.Type.String(),
		Version: version,
	}

	keyJSON, err := json.Marshal(encryptedKeyJSONV3)
	if err != nil {
		return err
	}

	return WriteKeyFile(key.Address, ks.keysDirPath, keyJSON)
}

func (ks keyStorePassphrase) DeleteKey(keyAddr []byte, auth string) (err error) {
	// only delete if correct passphrase is given
	_, err = DecryptKey(ks, keyAddr, auth)
	if err != nil {
		return err
	}

	keyDirPath := path.Join(ks.keysDirPath, strings.ToUpper(hex.EncodeToString(keyAddr)))
	return os.RemoveAll(keyDirPath)
}

// TODO: update for versions
func IsEncryptedKey(ks KeyStore, keyAddr []byte) (bool, error) {
	kspp, ok := ks.(*keyStorePassphrase)
	if !ok {
		return false, fmt.Errorf("only keyStorePassphrase can handle encrypted key files")
	}

	fileContent, err := GetKeyFile(kspp.keysDirPath, keyAddr)
	if err != nil {
		return false, err
	}

	keyProtected := new(encryptedKeyJSONv0)
	if err = json.Unmarshal(fileContent, keyProtected); err != nil {
		return false, err
	}
	return len(keyProtected.Crypto.CipherText) > 0, nil
}

func DecryptKey(ks keyStorePassphrase, keyAddr []byte, auth string) (key *Key, err error) {
	m := make(map[string]interface{})
	err = GetKey(ks.keysDirPath, keyAddr, &m)
	if err != nil {
		return
	}

	v := reflect.ValueOf(m["version"])
	if v.Kind() == reflect.String && v.String() == "1" {
		k := new(encryptedKeyJSONv0)
		err = GetKey(ks.keysDirPath, keyAddr, &k)
		if err != nil {
			return
		}
		return decryptKeyV0(k, keyAddr, auth)
	} else {
		k := new(encryptedKeyJSONv3)
		err = GetKey(ks.keysDirPath, keyAddr, &k)
		if err != nil {
			return
		}
		return decryptKeyV3(k, keyAddr, auth)
	}
}

func decryptKeyV3(keyProtected *encryptedKeyJSONv3, keyAddr []byte, auth string) (*Key, error) {
	if keyProtected.Version != version {
		return nil, fmt.Errorf("Version not supported: %v", keyProtected.Version)
	}

	// TODO: support CTR too ...
	if keyProtected.Crypto.Cipher != "aes-128-gcm" {
		return nil, fmt.Errorf("Cipher not supported: %v", keyProtected.Crypto.Cipher)
	}

	keyId := uuid.Parse(keyProtected.Id)
	keyType, err := KeyTypeFromString(keyProtected.Type)
	if err != nil {
		return nil, err
	}

	keyAddr2, err := hex.DecodeString(keyProtected.Address)
	if bytes.Compare(keyAddr, keyAddr2) != 0 {
		return nil, fmt.Errorf("address of key and address in file do not match. Got %x, expected %x", keyAddr2, keyAddr)
	}
	//salt := keyProtected.Crypto.Salt

	nonce, err := hex.DecodeString(keyProtected.Crypto.CipherParams.Nonce)
	if err != nil {
		return nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, auth)
	if err != nil {
		return nil, err
	}

	/*authArray := []byte(auth)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptr, scryptp, scryptdkLen)
	if err != nil {
		return nil, err
	}*/
	plainText, err := aesGCMDecrypt(derivedKey, cipherText, nonce)
	if err != nil {
		return nil, err
	}

	// no need to use a checksum as done by gcm

	// TODO: !!
	return &Key{
		Id:         uuid.UUID(keyId),
		Type:       keyType,
		Address:    keyAddr,
		PrivateKey: plainText,
	}, nil
}

func getKDFKey(cryptoJSON cryptoJSON, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(cryptoJSON.KDFParams["dklen"])

	if cryptoJSON.KDF == "scrypt" {
		n := ensureInt(cryptoJSON.KDFParams["n"])
		r := ensureInt(cryptoJSON.KDFParams["r"])
		p := ensureInt(cryptoJSON.KDFParams["p"])
		return scrypt.Key(authArray, salt, n, r, p, dkLen)

	} else if cryptoJSON.KDF == "pbkdf2" {
		c := ensureInt(cryptoJSON.KDFParams["c"])
		prf := cryptoJSON.KDFParams["prf"].(string)
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("Unsupported PBKDF2 PRF: ", prf)
		}
		key := pbkdf2.Key(authArray, salt, c, dkLen, sha256.New)
		return key, nil
	}

	return nil, fmt.Errorf("Unsupported KDF: ", cryptoJSON.KDF)
}

func decryptKeyV0(keyProtected *encryptedKeyJSONv0, keyAddr []byte, auth string) (*Key, error) {

	keyId := keyProtected.Id
	keyType, err := KeyTypeFromString(keyProtected.Type)
	if err != nil {
		return nil, err
	}

	keyAddr2, err := hex.DecodeString(keyProtected.Address)
	if bytes.Compare(keyAddr, keyAddr2) != 0 {
		return nil, fmt.Errorf("address of key and address in file do not match. Got %x, expected %x", keyAddr2, keyAddr)
	}
	salt := keyProtected.Crypto.Salt
	nonce := keyProtected.Crypto.Nonce
	cipherText := keyProtected.Crypto.CipherText

	authArray := []byte(auth)
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptr, scryptp, scryptdkLen)
	if err != nil {
		return nil, err
	}
	plainText, err := aesGCMDecrypt(derivedKey, cipherText, nonce)
	if err != nil {
		return nil, err
	}

	// no need to use a checksum as done by gcm

	return &Key{
		Id:         uuid.UUID(keyId),
		Type:       keyType,
		Address:    keyAddr,
		PrivateKey: plainText,
	}, nil
}

func aesGCMDecrypt(key []byte, cipherText []byte, nonce []byte) (plainText []byte, err error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}

	paddedPlainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	plainText = util.PKCS7Unpad(paddedPlainText)
	if plainText == nil {
		err = fmt.Errorf("Decryption failed: PKCS7Unpad failed after decryption")
	}
	return plainText, err
}

//-----------------------------------------------------------------------------
// json encodings

// addresses should be hex encoded

type plainKeyJSONv0 struct {
	Id         []byte
	Type       string
	Address    string
	PrivateKey []byte
}

type encryptedKeyJSONv0 struct {
	Id      []byte
	Type    string
	Address string
	Crypto  cipherJSONv0
}

type cipherJSONv0 struct {
	Salt       []byte
	Nonce      []byte
	CipherText []byte
}

type plainKeyJSONv3 struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privatekey"`
	Id         string `json:"id"`
	Type       string `json:"type"`
	Version    int    `json:"version"`
}

type encryptedKeyJSONv3 struct {
	Address string `json:"address"`
	Crypto  cryptoJSON
	Id      string `json:"id"`
	Type    string `json:"type"`
	Version int    `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"` // no need (for gcm)
}

type cipherparamsJSON struct {
	Nonce string `json:"nonce"`
}

type scryptParamsJSON struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DkLen int    `json:"dklen"`
	Salt  string `json:"salt"`
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	jStruct := plainKeyJSONv3{
		Address:    fmt.Sprintf("%X", k.Address), // upper case
		PrivateKey: fmt.Sprintf("%X", k.PrivateKey),
		Id:         k.Id.String(),
		Type:       k.Type.String(),
		Version:    version,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	// TODO: check version first

	keyJSON := new(plainKeyJSONv3)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}
	// TODO: remove this
	if len(keyJSON.PrivateKey) == 0 {
		return NoPrivateKeyErr("")
	}

	u := new(uuid.UUID)
	*u = uuid.Parse(keyJSON.Id)
	k.Id = *u
	k.Address, err = hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	k.PrivateKey, err = hex.DecodeString(keyJSON.PrivateKey)
	if err != nil {
		return err
	}
	k.Type, err = KeyTypeFromString(keyJSON.Type)
	return err
}

// returns the address if valid, nil otherwise
func IsValidKeyJson(j []byte) []byte {
	// TODO: check version first

	j1 := new(plainKeyJSONv3)
	e1 := json.Unmarshal(j, &j1)
	if e1 == nil {
		addr, _ := hex.DecodeString(j1.Address)
		return addr
	}

	j2 := new(encryptedKeyJSONv3)
	e2 := json.Unmarshal(j, &j2)
	if e2 == nil {
		addr, _ := hex.DecodeString(j2.Address)
		return addr
	}

	return nil
}

// TODO: can we do without this when unmarshalling dynamic JSON?
// why do integers in KDF params end up as float64 and not int after
// unmarshal?
func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}
