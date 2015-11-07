package main

import (
	"fmt"

	commands "github.com/eris-ltd/eris-keys/eris-keys"
	"github.com/eris-ltd/eris-keys/version"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common/go/common"
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
	os.MkdirAll(RENDER_DIR, 0775)
	eris := commands.EKeys
	specs := common.GenerateSpecs(SPECS_DIR, RENDER_DIR, FRONT_MATTER)
	common.GenerateTree(epm, RENDER_DIR, specs, FRONT_MATTER, BASE_URL)
}
