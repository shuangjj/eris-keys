package wire

import (
	"github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/shuangjj/tendermint/logger"
	"github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/tendermint/log15"
)

var log = logger.New("module", "binary")

func init() {
	log.SetHandler(
		log15.LvlFilterHandler(
			log15.LvlWarn,
			//log15.LvlDebug,
			logger.RootHandler(),
		),
	)
}
