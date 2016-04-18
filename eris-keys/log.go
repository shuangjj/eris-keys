package keys

import (
	. "github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/shuangjj/common/go/log"
)

var logger *Logger

func initLog() {
	logger = AddLogger("commands")
}
