package commands

import (
	"fmt"
	"os"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common"
)

var (
	DefaultKeyType  = "ed25519,ripemd160"
	DefaultDir      = common.Keys
	DefaultAuth     = ""
	DefaultHashType = "sha256"

	DefaultHost = "localhost"
	DefaultPort = "4767"
	DefaultAddr = "http://" + DefaultHost + ":" + DefaultPort
	TestPort    = "7674"
	TestAddr    = "http://" + DefaultHost + ":" + TestPort
)

func DefineApp() *cli.App {
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
		hashCmd,
		serverCmd,
		importCmd,
	}
	return app
}

var (
	keygenCmd = cli.Command{
		Name:   "gen",
		Usage:  "generate a key",
		Action: cliKeygen,
		Flags: []cli.Flag{
			keyTypeFlag,
			dirFlag,
			authFlag,
		},
	}

	signCmd = cli.Command{
		Name:   "sign",
		Usage:  "eris-keys sign <hash> <address>",
		Action: cliSign,
		Flags: []cli.Flag{
			dirFlag,
			authFlag,
		},
	}

	pubKeyCmd = cli.Command{
		Name:   "pub",
		Usage:  "eris-keys pub <addr>",
		Action: cliPub,
		Flags: []cli.Flag{
			dirFlag,
			authFlag,
		},
	}

	verifyCmd = cli.Command{
		Name:   "verify",
		Usage:  "eris-keys verify <addr> <hash> <sig>",
		Action: cliVerify,
		Flags: []cli.Flag{
			dirFlag,
			authFlag,
		},
	}

	hashCmd = cli.Command{
		Name:   "hash",
		Usage:  "eris-keys hash <some data>",
		Action: cliHash,
		Flags: []cli.Flag{
			hashTypeFlag,
		},
	}

	serverCmd = cli.Command{
		Name:   "server",
		Usage:  "eris-keys server",
		Action: cliServer,
		Flags: []cli.Flag{
			hostFlag,
			portFlag,
		},
	}

	importCmd = cli.Command{
		Name:   "import",
		Usage:  "eris-keys import <priv key>",
		Action: cliImport,
		Flags: []cli.Flag{
			keyTypeFlag,
			dirFlag,
			authFlag,
		},
	}

	keyTypeFlag = cli.StringFlag{
		Name:  "type",
		Value: DefaultKeyType,
		Usage: "specify the type of key to create. Supports 'secp256k1,sha3' (ethereum),  'secp256k1,ripemd160sha2' (bitcoin), 'ed25519,ripemd160' (tendermint)",
	}

	hashTypeFlag = cli.StringFlag{
		Name:  "type",
		Value: DefaultHashType,
		Usage: "specify the hash function to use",
	}

	dirFlag = cli.StringFlag{
		Name:  "dir",
		Value: DefaultDir,
		Usage: "specify the location of the directory containing key files",
	}

	authFlag = cli.StringFlag{
		Name:  "auth",
		Value: "",
		Usage: "a password to be used for encrypting keys",
	}

	hostFlag = cli.StringFlag{
		Name:  "host",
		Value: DefaultHost,
		Usage: "set the host for key daemon to listen on",
	}

	portFlag = cli.StringFlag{
		Name:  "port",
		Value: DefaultPort,
		Usage: "set the port for key daemon to listen on",
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
