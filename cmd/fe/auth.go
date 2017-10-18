package main

import (
	"encoding/json"
	"github.com/CodisLabs/codis/pkg/utils/log"
	"github.com/go-martini/martini"
	"io/ioutil"
	"net/http"
	"strings"
)

type AuthConfig struct {
	TrustableIps []string `json:"TrustIps"`
}

var authConfigInstance *AuthConfig

func fileToString(filePath string) (string, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func fileToTrimString(filePath string) (string, error) {
	str, err := fileToString(filePath)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(str), nil
}

func containsString(sl []string, v string) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}

func LoadAuthConfig(path string) {
	var c AuthConfig
	content, err := fileToTrimString(path)
	if err != nil {
		log.PanicError(err, "read config file: %s failed:", path)
	}
	err = json.Unmarshal([]byte(content), &c)
	if err != nil {
		log.PanicError(err, "read config file: %s failed:", path)
	}
	authConfigInstance = &c
}

func CheckTrustable() martini.Handler {
	return func(res http.ResponseWriter, req *http.Request, c martini.Context) {
		if authConfigInstance == nil {
			LoadAuthConfig("fe.auth.json")
		}

		ip := req.RemoteAddr
		idx := strings.LastIndex(req.RemoteAddr, ":")
		if idx > 0 {
			ip = req.RemoteAddr[0:idx]
		}

		if ip == "127.0.0.1" {
			return
		}

		if !containsString(authConfigInstance.TrustableIps, ip) {
			http.Error(res, "Not Authorized", http.StatusUnauthorized)
			return
		}
	}
}
