package commands

import (
	"encoding/json"
	"fmt"

	"github.com/eris-ltd/eris-keys/manager"

	. "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/common"

	//"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/howeyc/gopass"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/spf13/cobra"
)

func ExitConnectErr(err error) {
	Exit(fmt.Errorf("Could not connect to eris-keys server. Start it with `eris-keys server &`. Error: %v", err))
}

func cliServer(cmd *cobra.Command, args []string) {
	ks, err := newKeyStore(KeysDir, true)
	IfExit(err)

	AccountManager = manager.NewManager(ks)

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
	fmt.Println(r)
}

func cliLock(cmd *cobra.Command, args []string) {
	r, err := Call("lock", map[string]string{"addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	fmt.Println(r)
}

func cliUnlock(cmd *cobra.Command, args []string) {
	auth := hiddenAuth()
	r, err := Call("unlock", map[string]string{"auth": auth, "addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	fmt.Println(r)
}

// since pubs are not saved, the key needs to be unlocked to get the pub
// TODO: save the pubkey (backwards compatibly...)
func cliPub(cmd *cobra.Command, args []string) {
	r, err := Call("pub", map[string]string{"addr": KeyAddr, "name": KeyName})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	fmt.Println(r)
}

func cliSign(cmd *cobra.Command, args []string) {
	dir, addr, name := KeysDir, KeyAddr, KeyName
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a msg/hash to sign"))
	}
	msg := args[0]
	r, err := Call("sign", map[string]string{"dir": dir, "addr": addr, "name": name, "msg": msg})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	fmt.Println(r)
}

func cliVerify(cmd *cobra.Command, args []string) {
	if len(args) != 2 {
		Exit(fmt.Errorf("enter a msg/hash and a signature"))
	}
	msg, sig := args[0], args[1]
	r, err := Call("verify", map[string]string{"addr": KeyAddr, "name": KeyName, "msg": msg, "sig": sig})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	fmt.Println(r)
}

func cliHash(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		Exit(fmt.Errorf("enter something to hash"))
	}
	msg := args[0]
	r, err := Call("hash", map[string]string{"type": KeyType, "msg": msg, "hex": fmt.Sprintf("%v", HexByte)})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	fmt.Println(r)
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
	fmt.Println(r)
}

func cliName(cmd *cobra.Command, args []string) {
	/*
		Options:
		- add/modify: eris-keys name <name> <address>
		- display address: eris-keys name <name>
		- rm (name): eris-keys name --rm <name>
		- ls: eris-keys name --ls
	*/
	rm, ls := RmKeyName, LsNameAddr
	var name, addr string
	if len(args) > 0 {
		name = args[0]
	}
	if len(args) > 1 {
		addr = args[1]
	}

	r, err := Call("name", map[string]string{"name": name, "addr": addr, "rm": fmt.Sprintf("%v", rm), "ls": fmt.Sprintf("%v", ls)})
	if _, ok := err.(ErrConnectionRefused); ok {
		ExitConnectErr(err)
	}
	IfExit(err)
	if ls {
		var names []string
		IfExit(json.Unmarshal([]byte(r), &names))
		for n, a := range names {
			fmt.Printf("%s: %s\n", n, a)
		}

	} else {
		fmt.Println(r)
	}
}
