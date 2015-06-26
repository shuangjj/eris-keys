package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/codegangsta/cli"
	. "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common"
)

// most commands require at least one of --name or --addr
func checkGetNameAddr(dir, name, addr string) string {
	if name == "" && addr == "" {
		Exit(fmt.Errorf("at least one of --name or --addr must be provided"))
	}

	// name takes precedent if both are given
	var err error
	if name != "" {
		addr, err = coreNameGet(dir, name)
		IfExit(err)
	}
	return addr
}

func cliKeygen(c *cli.Context) {
	dir, auth, keyType, name := c.String("dir"), c.String("auth"), c.String("type"), c.String("name")
	addr, err := coreKeygen(dir, auth, keyType)
	IfExit(err)
	if name != "" {
		IfExit(coreNameAdd(dir, name, hex.EncodeToString(addr)))
	}
	fmt.Printf("%X\n", addr)
}

func cliSign(c *cli.Context) {
	args := c.Args()
	auth, dir, addr, name := c.String("auth"), c.String("dir"), c.String("addr"), c.String("name")
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a msg/hash to sign"))
	}
	msg := args[0]
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
	addr = checkGetNameAddr(dir, name, addr)
	res, err := coreVerify(dir, auth, addr, msg, sig)
	IfExit(err)
	fmt.Println(res)
}

func cliPub(c *cli.Context) {
	auth, dir, addr, name := c.String("auth"), c.String("dir"), c.String("addr"), c.String("name")
	addr = checkGetNameAddr(dir, name, addr)
	pub, err := corePub(dir, auth, addr)
	IfExit(err)
	fmt.Printf("%X\n", pub)
}

func cliHash(c *cli.Context) {
	args := c.Args()
	if len(args) != 1 {
		Exit(fmt.Errorf("enter something to hash"))
	}
	typ := c.String("type")
	toHash := args[0]
	hash, err := coreHash(typ, toHash)
	IfExit(err)
	fmt.Printf("%X\n", hash)
}

func cliServer(c *cli.Context) {
	host, port := c.String("host"), c.String("port")
	IfExit(ListenAndServe(host, port))
}

func cliImport(c *cli.Context) {
	args := c.Args()
	if len(args) != 1 {
		Exit(fmt.Errorf("enter a private key or filename"))
	}
	auth, dir, name := c.String("auth"), c.String("dir"), c.String("name")
	keyType := c.String("type")
	key := args[0]

	addr, err := coreImport(dir, auth, keyType, key)
	IfExit(err)

	if name != "" {
		IfExit(coreNameAdd(dir, name, hex.EncodeToString(addr)))
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

	if ls {
		names, err := coreNameList(dir)
		IfExit(err)
		for n, a := range names {
			fmt.Printf("%s: %s\n", n, a)
		}
		return
	}

	if len(c.Args()) == 0 {
		Exit(fmt.Errorf("please specify a name"))
	}
	name := c.Args()[0]

	if rm {
		IfExit(coreNameRm(dir, name))
		return
	}

	if len(c.Args()) > 1 {
		addr := c.Args()[1]
		IfExit(coreNameAdd(dir, name, addr))
	} else {
		addr, err := coreNameGet(dir, name)
		IfExit(err)
		fmt.Println(addr)
	}
}
