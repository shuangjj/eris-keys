package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/spf13/cobra"
	"strings"

	. "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/common"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/howeyc/gopass"
)

func cliServer(cmd *cobra.Command, args []string) {
	host, port := KeyHost, KeyPort
	IfExit(ListenAndServe(host, port))
}

func hiddenAuth(authB bool) string {
	var auth string
	if authB {
		fmt.Printf("Enter Password:")
		pwd := gopass.GetPasswdMasked()
		auth = string(pwd)
	}
	return auth
}

func cliKeygen(cmd *cobra.Command, args []string) {
	dir, authB, keyType, name := KeysDir, KeyAuth, KeyType, KeyName
	//auth := hiddenAuth(authB)
	auth := authB
	if UseDaemon {
		r, err := Call("gen", map[string]string{"dir": dir, "auth": auth, "type": keyType, "name": name})
		if _, ok := err.(ErrConnectionRefused); !ok {
			IfExit(err)
			fmt.Println(r)
			return
		}
	}
	addr, err := coreKeygen(dir, auth, keyType)
	IfExit(err)
	if name != "" {
		IfExit(coreNameAdd(dir, name, strings.ToUpper(hex.EncodeToString(addr))))
	}
	logger.Printf("%X\n", addr)
}

func cliPub(cmd *cobra.Command, args []string) {
	auth, dir, addr, name := KeyAuth, KeysDir, KeyAddr, KeyName
	//auth := hiddenAuth(authB)
	if UseDaemon {
		r, err := Call("pub", map[string]string{"dir": dir, "auth": auth, "addr": addr, "name": name})
		if _, ok := err.(ErrConnectionRefused); !ok {
			IfExit(err)
			fmt.Println(r)
			return
		}
	}
	addr = checkGetNameAddr(dir, name, addr)
	pub, err := corePub(dir, auth, addr)
	IfExit(err)
	fmt.Printf("%X\n", pub)
}

func cliSign(cmd *cobra.Command, args []string) {
	auth, dir, addr, name := KeyAuth, KeysDir, KeyAddr, KeyName
	//auth := hiddenAuth(authB)
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a msg/hash to sign"))
	}
	msg := args[0]
	if UseDaemon {
		r, err := Call("sign", map[string]string{"dir": dir, "auth": auth, "addr": addr, "name": name, "msg": msg})
		if _, ok := err.(ErrConnectionRefused); !ok {
			IfExit(err)
			fmt.Println(r)
			return
		}
	}

	addr = checkGetNameAddr(dir, name, addr)
	sig, err := coreSign(dir, auth, msg, addr)
	IfExit(err)
	fmt.Printf("%X\n", sig)
}

func cliVerify(cmd *cobra.Command, args []string) {
	auth, dir, addr, name := KeyAuth, KeysDir, KeyAddr, KeyName
	//auth := hiddenAuth(authB)
	if len(args) != 2 {
		Exit(fmt.Errorf("enter a msg/hash and a signature"))
	}
	msg, sig := args[0], args[1]
	if UseDaemon {
		r, err := Call("verify", map[string]string{"dir": dir, "auth": auth, "addr": addr, "name": name, "msg": msg, "sig": sig})
		if _, ok := err.(ErrConnectionRefused); !ok {
			IfExit(err)
			fmt.Println(r)
			return
		}
	}
	addr = checkGetNameAddr(dir, name, addr)
	res, err := coreVerify(dir, auth, addr, msg, sig)
	IfExit(err)
	fmt.Println(res)
}

func cliHash(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		Exit(fmt.Errorf("enter something to hash"))
	}
	typ, hexD := KeyType, HexByte
	msg := args[0]
	if UseDaemon {
		r, err := Call("hash", map[string]string{"type": typ, "msg": msg, "hex": fmt.Sprintf("%v", hexD)})
		if _, ok := err.(ErrConnectionRefused); !ok {
			IfExit(err)
			fmt.Println(r)
			return
		}
	}
	hash, err := coreHash(typ, msg, hexD)
	IfExit(err)
	fmt.Printf("%X\n", hash)
}

func cliImport(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a private key or filename"))
	}
	auth, dir, name := KeyAuth, KeysDir, KeyName
	//auth := hiddenAuth(authB)
	keyType := KeyType
	key := args[0]
	if UseDaemon {
		r, err := Call("import", map[string]string{"dir": dir, "auth": auth, "name": name, "type": keyType, "key": key})
		if _, ok := err.(ErrConnectionRefused); !ok {
			IfExit(err)
			fmt.Println(r)
			return
		}
	}

	addr, err := coreImport(dir, auth, keyType, key)
	IfExit(err)

	if name != "" {
		IfExit(coreNameAdd(dir, name, strings.ToUpper(hex.EncodeToString(addr))))
	}
	fmt.Printf("%X\n", addr)
}

func cliName(cmd *cobra.Command, args []string) {
	/*
		Options:
		- add/modify: eris-keys name <name> <address>
		- display address: eris-keys name <name>
		- rm (name): eris-keys name --rm <name>
		- ls: eris-keys name --ls
	*/
	dir, rm, ls := KeysDir, RmKeyName, LsNameAddr
	var name, addr string
	if len(args) > 0 {
		name = args[0]
	}
	if len(args) > 1 {
		addr = args[1]
	}

	if UseDaemon {
		r, err := Call("name", map[string]string{"dir": dir, "name": name, "addr": addr, "rm": fmt.Sprintf("%v", rm), "ls": fmt.Sprintf("%v", ls)})
		if _, ok := err.(ErrConnectionRefused); !ok {
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
			return
		}
	}
	if ls {
		names, err := coreNameList(dir)
		IfExit(err)
		for n, a := range names {
			fmt.Printf("%s: %s\n", n, a)
		}

		addrs, err := coreAddrList(dir)
		IfExit(err)
		for c, a := range addrs {
			fmt.Printf("%d: %s\n", c, a)
		}
		return
	}

	if name == "" {
		Exit(fmt.Errorf("please specify a name"))
	}

	if rm {
		IfExit(coreNameRm(dir, name))
		return
	}

	if addr != "" {
		addr := args[1]
		IfExit(coreNameAdd(dir, name, strings.ToUpper(addr)))
	} else {
		addr, err := coreNameGet(dir, name)
		IfExit(err)
		fmt.Println(strings.ToUpper(addr))
	}
}
