package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/rs/cors"
)

//------------------------------------------------------------------------
// http server exports same commands as the cli
// all request arguments are keyed and passed through header
// body is ignored

func ListenAndServe(host, port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/gen", genHandler)
	mux.HandleFunc("/pub", pubHandler)
	mux.HandleFunc("/sign", signHandler)
	mux.HandleFunc("/verify", verifyHandler)
	mux.HandleFunc("/hash", hashHandler)
	mux.HandleFunc("/import", importHandler)
	mux.HandleFunc("/name", nameHandler)
	if os.Getenv("ERIS_KEYS_HOST") != "" {
		host = os.Getenv("ERIS_KEYS_HOST")
	}
	if os.Getenv("ERIS_KEYS_PORT") != "" {
		port = os.Getenv("ERIS_KEYS_PORT")
	}

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"}, // TODO: dev
	})
	return http.ListenAndServe(host+":"+port, c.Handler(mux))
}

type HTTPRequest map[string]string

// dead simple response struct
type HTTPResponse struct {
	Response string
	Error    string
}

func WriteResult(w http.ResponseWriter, result string) {
	resp := HTTPResponse{result, ""}
	b, _ := json.Marshal(resp)
	w.Write(b)
}

func WriteError(w http.ResponseWriter, err error) {
	resp := HTTPResponse{"", err.Error()}
	b, _ := json.Marshal(resp)
	w.Write(b)
}

//------------------------------------------------------------------------
// handlers

func genHandler(w http.ResponseWriter, r *http.Request) {
	typ, dir, auth, args, err := typeDirAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}

	name := args["name"]
	addr, err := coreKeygen(dir, auth, typ)
	if err != nil {
		WriteError(w, err)
		return
	}
	if name != "" {
		err := coreNameAdd(dir, name, strings.ToUpper(hex.EncodeToString(addr)))
		if err != nil {
			WriteError(w, err)
			return
		}
	}
	WriteResult(w, fmt.Sprintf("%X", addr))
}

func pubHandler(w http.ResponseWriter, r *http.Request) {
	_, dir, auth, args, err := typeDirAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	addr, name := args["addr"], args["name"]
	addr, err = getNameAddr(dir, name, addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	pub, err := corePub(dir, auth, addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, fmt.Sprintf("%X", pub))
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	_, dir, auth, args, err := typeDirAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	addr, name := args["addr"], args["name"]
	addr, err = getNameAddr(dir, name, addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	hash := args["hash"]
	if hash == "" {
		WriteError(w, fmt.Errorf("must provide a message hash with the `hash` key"))
		return
	}
	sig, err := coreSign(dir, auth, hash, addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, fmt.Sprintf("%X", sig))
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	_, dir, auth, args, err := typeDirAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	addr, name := args["addr"], args["name"]
	addr, err = getNameAddr(dir, name, addr)
	if err != nil {
		WriteError(w, err)
		return
	}
	hash := args["hash"]
	if hash == "" {
		WriteError(w, fmt.Errorf("must provide a message hash with the `hash` key"))
		return
	}
	sig := args["sig"]
	if sig == "" {
		WriteError(w, fmt.Errorf("must provide a signature with the `sig` key"))
		return
	}

	res, err := coreVerify(dir, auth, addr, hash, sig)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, fmt.Sprintf("%v", res))
}

func hashHandler(w http.ResponseWriter, r *http.Request) {
	typ, _, _, args, err := typeDirAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	msg := args["msg"]
	hexD := args["hex"]

	hash, err := coreHash(typ, msg, hexD == "true")
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, fmt.Sprintf("%X", hash))
}

func importHandler(w http.ResponseWriter, r *http.Request) {
	typ, dir, auth, args, err := typeDirAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	name := args["data"]
	key := args["key"]

	addr, err := coreImport(dir, auth, typ, key)
	if err != nil {
		WriteError(w, err)
		return
	}

	if name != "" {
		if err := coreNameAdd(dir, name, strings.ToUpper(hex.EncodeToString(addr))); err != nil {
			WriteError(w, err)
			return
		}
	}
	WriteResult(w, fmt.Sprintf("%X", addr))
}

func nameHandler(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Path[len("name"):]
	_, _, _, args, err := typeDirAuthArgs(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	dir := args["dir"]
	name := args["name"]
	addr := args["addr"]

	if action == "ls" {
		names, err := coreNameList(dir)
		if err != nil {
			WriteError(w, err)
			return
		}

		b, err := json.Marshal(names)
		if err != nil {
			WriteError(w, err)
			return
		}
		WriteResult(w, string(b))
		return
	}

	if name == "" {
		WriteError(w, fmt.Errorf("please specify a name"))
		return
	}

	if action == "rm" {
		if err := coreNameRm(dir, name); err != nil {
			WriteError(w, err)
			return
		}
	}

	if addr == "" {
		addr, err := coreNameGet(dir, name)
		if err != nil {
			WriteError(w, err)
			return
		}
		WriteResult(w, addr)
	} else {
		if err := coreNameAdd(dir, name, strings.ToUpper(addr)); err != nil {
			WriteError(w, err)
			return
		}
	}
}

func typeDirAuth(r *http.Request) (string, string, string) {
	return DefaultKeyType, DefaultDir, DefaultAuth
}

// convenience function
func typeDirAuthArgs(r *http.Request) (typ string, dir string, auth string, args map[string]string, err error) {

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}

	logger.Debugln("Request body:", string(b))

	if err = json.Unmarshal(b, &args); err != nil {
		return
	}

	typ = args["type"]
	if typ == "" {
		typ = DefaultKeyType
	}

	dir = args["dir"]
	if dir == "" {
		dir = DefaultDir
	}

	auth = args["auth"]
	if auth == "" {
		auth = DefaultAuth
	}

	return
}
