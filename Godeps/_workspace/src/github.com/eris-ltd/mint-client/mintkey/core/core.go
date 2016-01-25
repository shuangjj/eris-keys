package core

import (
	. "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/common"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/tendermint/account"
	kstore "github.com/eris-ltd/eris-keys/crypto"
)

type PrivValidator struct {
	Address    []byte                 `json:"address"`
	PubKey     account.PubKeyEd25519  `json:"pub_key"`
	PrivKey    account.PrivKeyEd25519 `json:"priv_key"`
	LastHeight int                    `json:"last_height"`
	LastRound  int                    `json:"last_round"`
	LastStep   int                    `json:"last_step"`
}

func CoreConvertErisKeyToPrivValidator(addrBytes []byte) (*PrivValidator, error) {
	keyStore := kstore.NewKeyStorePlain(KeysDataPath)
	key, err := keyStore.GetKey(addrBytes, "")
	IfExit(err)

	pub, err := key.Pubkey()
	if err != nil {
		return nil, err
	}

	var pubKey account.PubKeyEd25519
	copy(pubKey[:], pub)

	var privKey account.PrivKeyEd25519
	copy(privKey[:], key.PrivateKey)

	return &PrivValidator{
		Address: addrBytes,
		PubKey:  pubKey,
		PrivKey: privKey,
	}, nil
}
