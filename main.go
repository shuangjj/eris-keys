package main

import (
	"fmt"
	"os"

	"github.com/codegangsta/cli"
	"github.com/eris-ltd/epm-go/utils"
)

func main() {
	app := cli.NewApp()
	app.Name = "eris-keys"
	app.Usage = "Generate and manage keys for producing signatures"
	app.Version = "0.0.1"
	app.Author = "Ethan Buchman"
	app.Email = "ethan@erisindustries.com"
	app.Commands = []cli.Command{
		keygenCmd,
		signCmd,
		verifyCmd,
		pubKeyCmd,
	}

	app.Run(os.Args)

}

var (
	keygenCmd = cli.Command{
		Name:   "gen",
		Usage:  "generate a key",
		Action: cliKeygen,
		Flags: []cli.Flag{
			typeFlag,
			dirFlag,
			authFlag,
		},
	}

	signCmd = cli.Command{
		Name:   "sign",
		Usage:  "eris-keys sign <hash> <address>",
		Action: cliSign,
		Flags: []cli.Flag{
			typeFlag,
			dirFlag,
			authFlag,
		},
	}

	pubKeyCmd = cli.Command{
		Name:   "pub",
		Usage:  "eris-keys pub <addr>",
		Action: cliPub,
		Flags: []cli.Flag{
			typeFlag,
			dirFlag,
			authFlag,
		},
	}

	verifyCmd = cli.Command{
		Name:   "verify",
		Usage:  "eris-keys verify <addr> <hash> <sig>",
		Action: cliVerify,
		Flags: []cli.Flag{
			typeFlag,
			dirFlag,
			authFlag,
		},
	}

	typeFlag = cli.StringFlag{
		Name:  "type",
		Value: "secp256k1",
		Usage: "specify the type of key to create. Supports 'secp256k1' and 'ed25519'",
	}

	dirFlag = cli.StringFlag{
		Name:  "dir",
		Value: utils.Keys,
		Usage: "specify the location of the directory containing key files",
	}

	authFlag = cli.StringFlag{
		Name:  "auth",
		Value: "",
		Usage: "a password to be used for encrypting keys",
	}
)

func exit(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func ifExit(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
