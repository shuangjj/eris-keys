package logger

import (
	cfg "github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/shuangjj/tendermint/config"
)

var config cfg.Config = nil

func init() {
	cfg.OnConfig(func(newConfig cfg.Config) {
		config = newConfig
		Reset() // reset log root upon config change.
	})
}
