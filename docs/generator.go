package main

import (
	"fmt"
	"os"

	commands "github.com/shuangjj/eris-keys/eris-keys"
	"github.com/shuangjj/eris-keys/version"

	"github.com/shuangjj/eris-keys/Godeps/_workspace/src/github.com/shuangjj/common/go/common"
)

var RENDER_DIR = fmt.Sprintf("./docs/eris-keys/%s/", version.VERSION)

var SPECS_DIR = "./docs/"

var BASE_URL = fmt.Sprintf("https://docs.erisindustries.com/documentation/eris-keys/%s/", version.VERSION)

const FRONT_MATTER = `---

layout:     documentation
title:      "Documentation | eris:keys | {{}}"

---

`

func main() {
	os.MkdirAll(RENDER_DIR, 0755)
	eris := commands.EKeys
	commands.BuildKeysCommand()
	specs := common.GenerateSpecs(SPECS_DIR, RENDER_DIR, FRONT_MATTER)
	common.GenerateTree(eris, RENDER_DIR, specs, FRONT_MATTER, BASE_URL)
}
