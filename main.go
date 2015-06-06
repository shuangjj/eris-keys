package main

import (
	"os"

	"github.com/eris-ltd/eris-keys/commands"
)

func main() {
	app := commands.DefineApp()
	app.Run(os.Args)
}
