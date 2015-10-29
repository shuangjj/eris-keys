package keys

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"

	kstore "github.com/eris-ltd/eris-keys/crypto"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/code.google.com/p/go-uuid/uuid"
	. "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/common"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/spf13/cobra"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/ed25519"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/tendermint/account"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/tendermint/wire"
)

func ExitConnectErr(err error) {
	Exit(fmt.Errorf("Could not connect to eris-keys server. Start it with `eris-keys server &`. Error: %v", err))
}

func cliServer(cmd *cobra.Command, args []string) {
	IfExit(StartServer(KeyHost, KeyPort))
}

func cliKeygen(cmd *cobra.Command, args []string) {
	var auth string
	if !NoPassword {
		auth = hiddenAuth()
	}

	r, err := Call("gen", map[string]string{"auth": auth, "type": KeyType, "name": KeyName})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

func cliLock(cmd *cobra.Command, args []string) {
	r, err := Call("lock", map[string]string{"addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

func cliUnlock(cmd *cobra.Command, args []string) {
	auth := hiddenAuth()
	r, err := Call("unlock", map[string]string{"auth": auth, "addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

// since pubs are not saved, the key needs to be unlocked to get the pub
// TODO: save the pubkey (backwards compatibly...)
func cliPub(cmd *cobra.Command, args []string) {
	r, err := Call("pub", map[string]string{"addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

func cliSign(cmd *cobra.Command, args []string) {
	_, addr, name := KeysDir, KeyAddr, KeyName
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a msg/hash to sign"))
	}
	msg := args[0]
	r, err := Call("sign", map[string]string{"addr": addr, "name": name, "msg": msg})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

func cliVerify(cmd *cobra.Command, args []string) {
	if len(args) != 3 {
		Exit(fmt.Errorf("enter a msg/hash, a signature, and a public key"))
	}
	msg, sig, pub := args[0], args[1], args[2]
	r, err := Call("verify", map[string]string{"type": KeyType, "pub": pub, "msg": msg, "sig": sig})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

func cliHash(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		Exit(fmt.Errorf("enter something to hash"))
	}
	msg := args[0]
	r, err := Call("hash", map[string]string{"type": HashType, "msg": msg, "hex": fmt.Sprintf("%v", HexByte)})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

// TODO: password
func cliImport(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a private key or filename"))
	}
	key := args[0]
	r, err := Call("import", map[string]string{"name": KeyName, "type": KeyType, "key": key})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

func cliName(cmd *cobra.Command, args []string) {
	var name, addr string
	if len(args) > 0 {
		name = args[0]
	}
	if len(args) > 1 {
		addr = args[1]
	}

	r, err := Call("name", map[string]string{"name": name, "addr": addr})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

func cliNameLs(cmd *cobra.Command, args []string) {
	r, err := Call("name/ls", map[string]string{})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	names := make(map[string]string)
	IfExit(json.Unmarshal([]byte(r), &names))
	for n, a := range names {
		logger.Printf("%s: %s\n", n, a)
	}
}

func cliNameRm(cmd *cobra.Command, args []string) {
	var name string
	if len(args) > 0 {
		name = args[0]
	}
	r, err := Call("name/rm", map[string]string{"name": name})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	logger.Println(r)
}

//---------------------------------------------------------------------
//from mint-client/mintkey/cli.go
func Pubkeyer(k *kstore.Key) ([]byte, error) {
	priv := k.PrivateKey
	privKeyBytes := new([64]byte)
	copy(privKeyBytes[:32], priv)
	pubKeyBytes := ed25519.MakePublicKey(privKeyBytes)
	return pubKeyBytes[:], nil
}

func init() {
	kstore.SetPubkeyer(Pubkeyer) //can this go somewhere else? persistentPreRun perhaps?
}

type PrivValidator struct {
	Address    []byte                 `json:"address"`
	PubKey     account.PubKeyEd25519  `json:"pub_key"`
	PrivKey    account.PrivKeyEd25519 `json:"priv_key"`
	LastHeight int                    `json:"last_height"`
	LastRound  int                    `json:"last_round"`
	LastStep   int                    `json:"last_step"`
}

func cliConvertErisKeyToPrivValidator(cmd *cobra.Command, args []string) {
	cmd.ParseFlags(args)
	if len(args) == 0 {
		Exit(fmt.Errorf("Please enter the address of your key"))
	}

	addr := args[0]
	addrBytes, err := hex.DecodeString(addr)
	IfExit(err)

	privVal, err := coreConvertErisKeyToPrivValidator(addrBytes)
	IfExit(err)

	fmt.Println(string(wire.JSONBytes(privVal)))
}

func coreConvertErisKeyToPrivValidator(addrBytes []byte) (*PrivValidator, error) {
	keyStore := kstore.NewKeyStorePlain(DefaultKeyStore)
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

func cliConvertPrivValidatorToErisKey(cmd *cobra.Command, args []string) {
	cmd.ParseFlags(args)
	if len(args) == 0 {
		Exit(fmt.Errorf("Please enter the path to the priv_validator.json"))
	}

	pvf := args[0]
	b, err := ioutil.ReadFile(pvf)
	IfExit(err)

	key, err := coreConvertPrivValidatorToErisKey(b)
	IfExit(err)

	fmt.Printf("%X\n", key.Address)
}

func coreConvertPrivValidatorToErisKey(b []byte) (key *kstore.Key, err error) {

	pv := new(PrivValidator)
	wire.ReadJSON(pv, b, &err)
	if err != nil {
		return nil, err
	}

	keyStore := kstore.NewKeyStorePlain(DefaultKeyStore)

	key = &kstore.Key{
		Id:         uuid.NewRandom(),
		Type:       kstore.KeyType{kstore.CurveTypeEd25519, kstore.AddrTypeRipemd160},
		Address:    pv.Address,
		PrivateKey: pv.PrivKey[:],
	}

	err = keyStore.StoreKey(key, "")
	return key, err
}
