package commands

import (
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
	app.Version = "0.1.0"
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
		nameCmd,
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
			nameFlag,
		},
	}

	nameCmd = cli.Command{
		Name:   "name",
		Usage:  "manage key names. `eris-keys name <name> <address>`",
		Action: cliName,
		Flags: []cli.Flag{
			dirFlag,
			rmFlag,
			lsFlag,
		},
	}

	signCmd = cli.Command{
		Name:   "sign",
		Usage:  "eris-keys sign --addr <address> <hash>",
		Action: cliSign,
		Flags: []cli.Flag{
			dirFlag,
			authFlag,
			nameFlag,
			addrFlag,
		},
	}

	pubKeyCmd = cli.Command{
		Name:   "pub",
		Usage:  "eris-keys pub --addr <addr>",
		Action: cliPub,
		Flags: []cli.Flag{
			dirFlag,
			authFlag,
			nameFlag,
			addrFlag,
		},
	}

	verifyCmd = cli.Command{
		Name:   "verify",
		Usage:  "eris-keys verify --addr <addr> <hash> <sig>",
		Action: cliVerify,
		Flags: []cli.Flag{
			dirFlag,
			authFlag,
			nameFlag,
			addrFlag,
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
			nameFlag,
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

	addrFlag = cli.StringFlag{
		Name:  "addr",
		Value: "",
		Usage: "address of key to use",
	}

	nameFlag = cli.StringFlag{
		Name:  "name",
		Value: "",
		Usage: "name of key to use",
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

	rmFlag = cli.BoolFlag{
		Name:  "rm",
		Usage: "remove a key's name",
	}

	lsFlag = cli.BoolFlag{
		Name:  "ls",
		Usage: "list all <name>:<address> pairs",
	}
)

func checkMakeDataDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}
