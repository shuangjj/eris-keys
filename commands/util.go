package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	. "github.com/eris-ltd/eris-keys/Godeps/_workspace/src/github.com/eris-ltd/common"
)

// most commands require at least one of --name or --addr
func checkGetNameAddr(dir, name, addr string) string {
	addr, err := getNameAddr(dir, name, addr)
	IfExit(err)
	return addr
}

// return addr from name or addr
func getNameAddr(dir, name, addr string) (string, error) {
	if name == "" && addr == "" {
		return "", fmt.Errorf("at least one of --name or --addr must be provided")
	}

	// name takes precedent if both are given
	var err error
	if name != "" {
		addr, err = coreNameGet(dir, name)
		if err != nil {
			return "", err
		}
	}
	return strings.ToUpper(addr), nil
}

//------------------------------------------------------------
// http client

func unpackResponse(resp *http.Response) (string, string, error) {
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	resp.Body.Close()
	r := new(HTTPResponse)
	if err := json.Unmarshal(b, r); err != nil {
		return "", "", err
	}
	return r.Response, r.Error, nil
}

type ErrConnectionRefused error

func requestResponse(req *http.Request) (string, string, error) {
	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", ErrConnectionRefused(err)
	}
	if resp.StatusCode >= 400 {
		return "", "", fmt.Errorf(resp.Status)
	}
	return unpackResponse(resp)
}

// Call the http server
func Call(method string, args map[string]string) (string, error) {
	url := fmt.Sprintf("%s/%s", DaemonAddr, method)
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range args {
		req.Header.Add(k, v)
	}
	r, errS, err := requestResponse(req)
	if err != nil {
		return "", err
	}
	if errS != "" {
		return "", fmt.Errorf(errS)
	}
	return r, nil
}
