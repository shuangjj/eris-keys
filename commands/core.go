package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/eris-ltd/eris-keys/crypto"
	"github.com/eris-ltd/eris-keys/manager"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/code.google.com/p/go.crypto/ripemd160"
)

var AccountManager *manager.Manager

func GetKey(addr []byte) (*crypto.Key, error) {
	k := AccountManager.GetKey(addr)
	if k != nil {
		return k, nil
	}
	// TODO: check and inform user if key exists but isn't unlocked
	keyStore, err := newKeyStore(KeysDir, false)
	if err != nil {
		return nil, err
	}
	return keyStore.GetKey(addr, "")
}

//-----

func returnDataDir(dir string) (string, error) {
	dir = path.Join(dir, "data")
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return dir, checkMakeDataDir(dir)
}

func returnNamesDir(dir string) (string, error) {
	dir = path.Join(dir, "names")
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return dir, checkMakeDataDir(dir)
}

//-----

// TODO: overwrite all mem buffers/registers?

func newKeyStore(dir string, auth bool) (keyStore crypto.KeyStore, err error) {
	dir, err = returnDataDir(dir)
	if err != nil {
		return nil, err
	}
	if auth {
		keyStore = crypto.NewKeyStorePassphrase(dir)
	} else {
		keyStore = crypto.NewKeyStorePlain(dir)
	}
	return
}

//----------------------------------------------------------------

// TODO: ...
func coreImport(auth, keyType, keyHex string) ([]byte, error) {
	return nil, nil
	/*
		keyStore, err := newKeyStore(dir, auth)
		if err != nil {
			return nil, err
		}

		// if the keyHex is actually json, make sure
		// its a valid key, write to file
		if len(keyHex) > 0 && keyHex[:1] == "{" {
			keyJson := []byte(keyHex)
			if addr := crypto.IsValidKeyJson(keyJson); addr != nil {
				dir, err = returnDataDir(dir)
				if err != nil {
					return nil, err
				}
				if err := ioutil.WriteFile(path.Join(dir, strings.ToUpper(hex.EncodeToString(addr))), keyJson, 0600); err != nil {
					return nil, err
				}
				return addr, nil
			} else {
				return nil, fmt.Errorf("invalid json key passed on command line")
			}
		}

		if _, err := os.Stat(keyHex); err == nil {
			keyJson, _ := ioutil.ReadFile(keyHex)
			if addr := crypto.IsValidKeyJson(keyJson); addr != nil {
				dir, err = returnDataDir(dir)
				if err != nil {
					return nil, err
				}
				if err := ioutil.WriteFile(path.Join(dir, strings.ToUpper(hex.EncodeToString(addr))), keyJson, 0600); err != nil {
					return nil, err
				}
				return addr, nil
			} else {
				return nil, fmt.Errorf("file was not a valid json key")
			}
		}

		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("private key is not a valid json key or known file, or is invalid hex: %v", err)
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
	*/
}

func coreKeygen(auth, keyType string) ([]byte, error) {
	var keyStore crypto.KeyStore
	var err error

	if auth == "" {
		keyStore, err = newKeyStore(KeysDir, false)
		if err != nil {
			return nil, err
		}
	} else {
		keyStore = AccountManager.KeyStore()
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

func coreSign(hash, addr string) ([]byte, error) {

	hashB, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("hash is invalid hex: %s", err.Error())
	}
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}

	key, err := GetKey(addrB)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key for %x: %v", addrB, err)
	}
	sig, err := key.Sign(hashB)
	if err != nil {
		return nil, fmt.Errorf("error signing %x using %x: %v", hashB, addrB, err)
	}
	return sig, nil
}

func coreVerify(auth, addr, hash, sig string) (result bool, err error) {
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

	// TODO: verify shouldnt require key
	key, err := GetKey(addrB)

	result, err = key.Verify(hashB, sigB)
	if err != nil {
		return result, fmt.Errorf("error verifying signature %x for address %x: %v", sigB, addrB, err)
	}

	return
}

func corePub(addr string) ([]byte, error) {
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("addr is invalid hex: %s", err.Error())
	}

	key, err := GetKey(addrB)
	if err != nil {
		return nil, fmt.Errorf("error retrieving key for %x: %v", addrB, err)
	}
	pub, err := key.Pubkey()
	if err != nil {
		return nil, fmt.Errorf("error retrieving pub key for %x: %v", addrB, err)
	}
	return pub, nil
}

func coreUnlock(auth, addr, timeout string) error {
	addrB, err := hex.DecodeString(addr)
	if err != nil {
		return fmt.Errorf("addr is invalid hex: %s", err.Error())
	}

	if _, err := GetKey(addrB); err == nil {
		return fmt.Errorf("Key is already unlocked or was never encrypted")
	}

	var timeoutD time.Duration
	if timeout != "" {
		t, err := strconv.ParseInt(timeout, 0, 64)
		if err != nil {
			return err
		}
		timeoutD = time.Duration(t)
	}

	if err := AccountManager.TimedUnlock(addrB, auth, timeoutD*time.Minute); err != nil {
		return err
	}
	return nil
}

func coreHash(typ, data string, hexD bool) ([]byte, error) {
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
	if hexD {
		d, err := hex.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("invalid hex")
		}
		hasher.Write(d)
	} else {
		io.WriteString(hasher, data)
	}
	return hasher.Sum(nil), nil
}

//----------------------------------------------------------------
// manage names for keys

func coreNameAdd(name, addr string) error {
	dir, err := returnNamesDir(KeysDir)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path.Join(dir, name), []byte(addr), 0600)
}

func coreNameList() (map[string]string, error) {
	dir, err := returnNamesDir(KeysDir)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string)
	fs, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		b, err := ioutil.ReadFile(path.Join(dir, f.Name()))
		if err != nil {
			return nil, err
		}
		names[f.Name()] = string(b)
	}
	return names, nil
}

func coreAddrList() (map[int]string, error) {
	dir, err := returnDataDir(KeysDir)
	if err != nil {
		return nil, err
	}
	addrs := make(map[int]string)
	fs, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(fs); i++ {
		addrs[i] = fs[i].Name()
	}
	return addrs, nil
}

func coreNameRm(name string) error {
	dir, err := returnNamesDir(KeysDir)
	if err != nil {
		return err
	}
	return os.Remove(path.Join(dir, name))
}

func coreNameGet(name string) (string, error) {
	dir, err := returnNamesDir(KeysDir)
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadFile(path.Join(dir, name))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
