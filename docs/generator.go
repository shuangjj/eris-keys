package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	// "sort"
	"strings"

	ekcmds "github.com/eris-ltd/eris-keys/commands"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/codegangsta/cli"
)

const (
	RENDER_DIR   = "./docs/eris-keys/"
	SPECS_DIR    = "./specs/"
	BASE_URL     = "https://docs.erisindustries.com/documentation/eris-keys/"
	FRONT_MATTER = `---

layout:     content
title:      "Documentation | eris:keys | {{}}"

---

`
)

// // Needed to sort properly
// type byName []*cli.Command
// func (s byName) Len() int           { return len(s) }
// func (s byName) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
// func (s byName) Less(i, j int) bool { return s[i].Name < s[j].Name }

func GenerateSingle(cmd *cli.Command, out *bytes.Buffer, linkHandler func(string) string, specs []string) {
	name := cmd.Name

	short := cmd.Usage
	long := cmd.Description
	if len(long) == 0 {
		long = short
	}

	fmt.Fprintf(out, "# %s\n\n", name)
	fmt.Fprintf(out, "%s\n\n", short)
	fmt.Fprintf(out, "## Synopsis\n")
	fmt.Fprintf(out, "\n%s\n\n", long)

	// if cmd.Runnable() {
	// 	fmt.Fprintf(out, "```bash\n%s\n```\n\n", name)
	// }

	// if len(cmd.Example) > 0 {
	// 	fmt.Fprintf(out, "## Examples\n\n")
	// 	fmt.Fprintf(out, "```bash\n%s\n```\n\n", cmd.Example)
	// }

	// flags := cmd.Flags
	// if len(flags) != 0 {
	// 	fmt.Fprintf(out, "## Options\n\n```\n")
	// 	for _, flag := range flags {
	// 		fmt.Fprintf(out, flag.Name + " - " + flag.Usage + "\n")
	// 	}
	// 	fmt.Fprintf(out, "```\n\n")
	// }

	// parentFlags := cmd.InheritedFlags()
	// parentFlags.SetOutput(out)
	// if parentFlags.HasFlags() {
	// 	fmt.Fprintf(out, "## Options inherited from parent commands\n\n```\n")
	// 	parentFlags.PrintDefaults()
	// 	fmt.Fprintf(out, "```\n\n")
	// }

	if len(cmd.Subcommands) > 0 {
		fmt.Fprintf(out, "## Subcommands\n\n")
		children := cmd.Subcommands

		for _, child := range children {
			// if len(child.Deprecated) > 0 {
			// 	continue
			// }
			cname := name + " " + child.Name
			link := cname + ".md"
			link = strings.Replace(link, " ", "_", -1)
			fmt.Fprintf(out, "* [%s](%s)\t - %s\n", cname, linkHandler(link), child.Usage)
		}
	}

	// if len(cmd.Subcommands) > 0 && cmd.HasParent() {
	// 	fmt.Fprintf(out, "\n")
	// }

	// if cmd.HasParent() {
	// 	fmt.Fprintf(out, "## See Also\n\n")
	// 	parent := cmd.Parent()
	// 	pname := parent.CommandPath()
	// 	link := pname + ".md"
	// 	link = strings.Replace(link, " ", "_", -1)
	// 	fmt.Fprintf(out, "* [%s](%s)\t - %s\n", pname, linkHandler(link), parent.Short)
	// }

	fmt.Fprintf(out, "\n## Specifications\n\n")
	for _, spec := range specs {
		spec = strings.Replace(spec, RENDER_DIR, "", 1)
		title := strings.Replace(spec, "_", " ", -1)
		title = strings.Replace(title, ".md", "", 1)
		title = strings.Replace(title, "spec", "specification", 1)
		title = strings.Title(title)
		fmt.Fprintf(out, "* [%s](%s)\n", title, linkHandler(spec))
	}

	fmt.Fprintf(out, "\n")
}

func GenerateTree(cmd *cli.Command, dir string, specs []string) {
	filePrepender := func(s string) string {
		s = strings.Replace(s, RENDER_DIR, "", 1)
		s = strings.Replace(s, ".md", "", -1)
		s = strings.Replace(s, "_", " ", -1)
		pre := strings.Replace(FRONT_MATTER, "{{}}", s, -1)
		return pre
	}

	linkHandler := func(s string) string {
		s = strings.Replace(s, ".md", "/", -1)
		link := BASE_URL + s
		return link
	}

	for _, c := range cmd.Subcommands {
		GenerateTree(&c, dir, specs)
	}
	out := new(bytes.Buffer)

	GenerateSingle(cmd, out, linkHandler, specs)

	filename := cmd.Name
	filename = dir + strings.Replace(filename, " ", "_", -1) + ".md"
	outFile, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer outFile.Close()

	_, err = outFile.WriteString(filePrepender(filename))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	_, err = outFile.Write(out.Bytes())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func GenerateSpecs(dir string) []string {
	files, _ := filepath.Glob(dir + "*.md")
	var outFiles []string

	for _, file := range files {
		specs := strings.Replace(SPECS_DIR, "./", "", 1)

		title := strings.Replace(file, specs, "", 1)
		fileBase := title
		title = strings.Replace(title, "_", " ", -1)
		title = strings.Replace(title, ".md", "", 1)
		title = strings.Replace(title, "spec", "specification", 1)
		title = strings.Title(title)

		pre := []byte(strings.Replace(FRONT_MATTER, "{{}}", title, -1))

		txt, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		out := append(pre, txt...)

		outFile := RENDER_DIR + fileBase
		err = ioutil.WriteFile(outFile, out, 0644)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		outFiles = append(outFiles, outFile)
	}

	return outFiles
}

func main() {
	os.MkdirAll(RENDER_DIR, 0775)
	eris := ekcmds.DefineApp().Commands
	specs := GenerateSpecs(SPECS_DIR)
	for _, e := range eris {
		GenerateTree(&e, RENDER_DIR, specs)
	}
}
