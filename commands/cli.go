package commands

import (
	"fmt"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/codegangsta/cli"
)

func cliKeygen(c *cli.Context) {
	dir, auth, keyType := c.String("dir"), c.String("auth"), c.String("type")
	addr, err := coreKeygen(dir, auth, keyType)
	ifExit(err)
	fmt.Printf("%X\n", addr)
}

func cliSign(c *cli.Context) {
	args := c.Args()
	auth, dir := c.String("auth"), c.String("dir")
	if len(args) != 2 {
		exit(fmt.Errorf("enter a hash and an address"))
	}
	hash, addr := args[0], args[1]
	sig, err := coreSign(dir, auth, hash, addr)
	ifExit(err)
	fmt.Printf("%X\n", sig)
}

func cliVerify(c *cli.Context) {
	args := c.Args()
	auth, dir := c.String("auth"), c.String("dir")
	if len(args) != 3 {
		exit(fmt.Errorf("enter an address, a hash, and a signature"))
	}
	addr, hash, sig := args[0], args[1], args[2]
	res, err := coreVerify(dir, auth, addr, hash, sig)
	ifExit(err)
	fmt.Println(res)
}

func cliPub(c *cli.Context) {
	args := c.Args()
	auth, dir := c.String("auth"), c.String("dir")
	if len(args) != 1 {
		exit(fmt.Errorf("enter an address"))
	}
	addr := args[0]
	pub, err := corePub(dir, auth, addr)
	ifExit(err)
	fmt.Printf("%X\n", pub)
}

func cliHash(c *cli.Context) {
	args := c.Args()
	if len(args) != 1 {
		exit(fmt.Errorf("enter something to hash"))
	}
	typ := c.String("type")
	toHash := args[0]
	hash, err := coreHash(typ, toHash)
	ifExit(err)
	fmt.Printf("%X\n", hash)
}

func cliServer(c *cli.Context) {
	host, port := c.String("host"), c.String("port")
	ifExit(ListenAndServe(host, port))
}

func cliImport(c *cli.Context) {
	args := c.Args()
	if len(args) != 1 {
		exit(fmt.Errorf("enter a private key or filename"))
	}
	auth, dir := c.String("auth"), c.String("dir")
	keyType := c.String("type")
	key := args[0]

	addr, err := coreImport(dir, auth, keyType, key)
	ifExit(err)
	fmt.Printf("%X\n", addr)

}
