package keys

import (
	"os"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/common"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/log"
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/spf13/cobra"
)

var (
	DefaultKeyType  = "ed25519,ripemd160"
	DefaultDir      = common.KeysPath
	DefaultHashType = "sha256"

	DefaultHost = "localhost"
	DefaultPort = "4767"
	DefaultAddr = "http://" + DefaultHost + ":" + DefaultPort
	TestPort    = "7674"
	TestAddr    = "http://" + DefaultHost + ":" + TestPort

	DaemonAddr = DefaultAddr

	/* flag vars */
	//global
	KeysDir string
	KeyName string
	KeyAddr string
	KeyHost string
	KeyPort string

	//keygenCmd only
	NoPassword bool
	KeyType    string

	//hashCmd only
	HashType string
	HexByte  bool

	//nameCmd only
	RmKeyName  bool
	LsNameAddr bool

	// lockCmd only
	UnlockTime int // minutes
)

var EKeys = &cobra.Command{
	Use:   "eris-keys",
	Short: "Generate and manage keys for producing signatures",
	Long:  "A tool for doing a bunch of cool stuff with keys.",
	Run:   func(cmd *cobra.Command, args []string) { cmd.Help() },
}

func Execute() {
	buildKeysCommand()
	EKeys.PersistentPostRun = after
	EKeys.Execute()
}

func buildKeysCommand() {
	EKeys.AddCommand(keygenCmd)
	EKeys.AddCommand(lockCmd)
	EKeys.AddCommand(unlockCmd)
	EKeys.AddCommand(nameCmd)
	EKeys.AddCommand(signCmd)
	EKeys.AddCommand(pubKeyCmd)
	EKeys.AddCommand(verifyCmd)
	EKeys.AddCommand(hashCmd)
	EKeys.AddCommand(serverCmd)
	EKeys.AddCommand(importCmd)
	addKeysFlags()
}

var keygenCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate a key",
	Long:  "Generates a key using (insert crypto pkgs used)",
	Run: func(cmd *cobra.Command, args []string) {
		cliKeygen(cmd, args)
	},
}

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "lock a key",
	Long:  "lock an unlocked key by re-encrypting it",
	Run: func(cmd *cobra.Command, args []string) {
		cliLock(cmd, args)
	},
}

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "unlock a key",
	Long:  "unlock an unlocked key by supplying the password",
	Run: func(cmd *cobra.Command, args []string) {
		cliUnlock(cmd, args)
	},
}

var nameCmd = &cobra.Command{
	Use:   "name",
	Short: "Manage key names. `eris-keys name <name> <address>`",
	Long:  "Manage key names. `eris-keys name <name> <address>`",
	Run: func(cmd *cobra.Command, args []string) {
		cliName(cmd, args)
	},
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "eris-keys sign --addr <address> <hash>",
	Long:  "eris-keys sign --addr <address> <hash>",
	Run: func(cmd *cobra.Command, args []string) {
		cliSign(cmd, args)
	},
}

var pubKeyCmd = &cobra.Command{
	Use:   "pub",
	Short: "eris-keys pub --addr <addr>",
	Long:  "eris-keys pub --addr <addr>",
	Run: func(cmd *cobra.Command, args []string) {
		cliPub(cmd, args)
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "eris-keys verify --addr <addr> <hash> <sig>",
	Long:  "eris-keys verify --addr <addr> <hash> <sig>",
	Run: func(cmd *cobra.Command, args []string) {
		cliVerify(cmd, args)
	},
}
var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "eris-keys hash <some data>",
	Long:  "eris-keys hash <some data>",
	Run: func(cmd *cobra.Command, args []string) {
		cliHash(cmd, args)
	},
}
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "eris-keys server",
	Long:  "eris-keys server",
	Run: func(cmd *cobra.Command, args []string) {
		cliServer(cmd, args)
	},
}
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "eris-keys import <priv key>",
	Long:  "eris-keys import <priv key>",
	Run: func(cmd *cobra.Command, args []string) {
		cliImport(cmd, args)
	},
}

func addKeysFlags() {
	EKeys.PersistentFlags().StringVarP(&KeysDir, "dir", "", DefaultDir, "specify the location of the directory containing key files")
	EKeys.PersistentFlags().StringVarP(&KeyName, "name", "", "", "name of key to use")
	EKeys.PersistentFlags().StringVarP(&KeyAddr, "addr", "", "", "address of key to use")
	EKeys.PersistentFlags().StringVarP(&KeyHost, "host", "", DefaultHost, "set the host for key daemon to listen on")
	EKeys.PersistentFlags().StringVarP(&KeyPort, "port", "", DefaultPort, "set the host for key daemon to listen on")

	keygenCmd.Flags().StringVarP(&KeyType, "type", "t", DefaultKeyType, "specify the type of key to create. Supports 'secp256k1,sha3' (ethereum),  'secp256k1,ripemd160sha2' (bitcoin), 'ed25519,ripemd160' (tendermint)")
	keygenCmd.Flags().BoolVarP(&NoPassword, "no-pass", "", false, "don't use a password for this key")

	hashCmd.PersistentFlags().StringVarP(&HashType, "type", "t", DefaultHashType, "specify the hash function to use")
	hashCmd.PersistentFlags().BoolVarP(&HexByte, "hex", "", false, "the input should be hex decoded to bytes first")

	//not sure if importCmd is correct. Check cliImport for more details
	importCmd.PersistentFlags().StringVarP(&KeyType, "type", "t", DefaultKeyType, "import a key")

	verifyCmd.PersistentFlags().StringVarP(&KeyType, "type", "t", DefaultKeyType, "key type")

	nameCmd.PersistentFlags().BoolVarP(&RmKeyName, "rm", "", false, "removes a key's name")
	nameCmd.PersistentFlags().BoolVarP(&LsNameAddr, "ls", "", false, "list all <name>:<address> pairs + un-named addresses")

	unlockCmd.PersistentFlags().IntVarP(&UnlockTime, "time", "t", 10, "number of minutes to unlock key for. defaults to 10, 0 for forever")
}

func checkMakeDataDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}
	}
	return nil
}

func after(cmd *cobra.Command, args []string) {
	log.Flush()
}
