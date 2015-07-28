package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/codegangsta/cli"
	. "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/common"
)

func cliServer(c *cli.Context) {
	host, port := c.String("host"), c.String("port")
	IfExit(ListenAndServe(host, port))
}

func cliKeygen(c *cli.Context) {
	dir, auth, keyType, name := c.String("dir"), c.String("auth"), c.String("type"), c.String("name")
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

func cliPub(c *cli.Context) {
	auth, dir, addr, name := c.String("auth"), c.String("dir"), c.String("addr"), c.String("name")
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

func cliSign(c *cli.Context) {
	args := c.Args()
	auth, dir, addr, name := c.String("auth"), c.String("dir"), c.String("addr"), c.String("name")
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

func cliVerify(c *cli.Context) {
	args := c.Args()
	auth, dir, addr, name := c.String("auth"), c.String("dir"), c.String("addr"), c.String("name")
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

func cliHash(c *cli.Context) {
	args := c.Args()
	if len(args) != 1 {
		Exit(fmt.Errorf("enter something to hash"))
	}
	typ, hexD := c.String("type"), c.Bool("hex")
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

func cliImport(c *cli.Context) {
	args := c.Args()
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a private key or filename"))
	}
	auth, dir, name := c.String("auth"), c.String("dir"), c.String("name")
	keyType := c.String("type")
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

func cliName(c *cli.Context) {
	/*
		Options:
		- add/modify: eris-keys name <name> <address>
		- display address: eris-keys name <name>
		- rm (name): eris-keys name --rm <name>
		- ls: eris-keys name --ls
	*/
	dir, rm, ls := c.String("dir"), c.Bool("rm"), c.Bool("ls")
	var name, addr string
	if len(c.Args()) > 0 {
		name = c.Args()[0]
	}
	if len(c.Args()) > 1 {
		addr = c.Args()[1]
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
		addr := c.Args()[1]
		IfExit(coreNameAdd(dir, name, strings.ToUpper(addr)))
	} else {
		addr, err := coreNameGet(dir, name)
		IfExit(err)
		fmt.Println(strings.ToUpper(addr))
	}
}
