package config

import (
	// We can't use github.com/eris-ltd/tendermint/logger
	// because that would create a dependency cycle.
	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/tendermint/log15"
)

var log = log15.New("module", "config")
