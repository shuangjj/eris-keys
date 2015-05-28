package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	return http.ListenAndServe(host+":"+port, mux)
}

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
	typ, dir, auth := typeDirAuth(r)
	addr, err := coreKeygen(dir, auth, typ)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, fmt.Sprintf("%X", addr))
}

func pubHandler(w http.ResponseWriter, r *http.Request) {
	_, dir, auth := typeDirAuth(r)
	addr := r.Header.Get("addr")
	if addr == "" {
		WriteError(w, fmt.Errorf("must provide an address with the `addr` key"))
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
	_, dir, auth := typeDirAuth(r)
	addr := r.Header.Get("addr")
	if addr == "" {
		WriteError(w, fmt.Errorf("must provide an address with the `addr` key"))
		return
	}
	hash := r.Header.Get("hash")
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
	_, dir, auth := typeDirAuth(r)
	addr := r.Header.Get("addr")
	if addr == "" {
		WriteError(w, fmt.Errorf("must provide an address with the `addr` key"))
		return
	}
	hash := r.Header.Get("hash")
	if hash == "" {
		WriteError(w, fmt.Errorf("must provide a message hash with the `hash` key"))
		return
	}
	sig := r.Header.Get("sig")
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
	typ, _, _ := typeDirAuth(r)
	data := r.Header.Get("data")

	hash, err := coreHash(typ, data)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteResult(w, fmt.Sprintf("%X", hash))
}

// convenience function
func typeDirAuth(r *http.Request) (string, string, string) {
	typ := r.Header.Get("type")
	if typ == "" {
		typ = DefaultKeyType
	}
	dir := r.Header.Get("dir")
	if dir == "" {
		dir = DefaultDir
	}
	auth := r.Header.Get("dir")
	if auth == "" {
		auth = DefaultAuth
	}
	return typ, dir, auth
}
