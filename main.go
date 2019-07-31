package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"nginx-mail-auth-http/types"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

func debugConfig(p interface{}) {
	x, _ := json.Marshal(p)
	fmt.Println(string(x))
}

func debugHeaders(headers http.Header) {
	b, err := json.MarshalIndent(headers, "", "  ")
	if err == nil {
		log.Println(string(b))
	}
}

func handleResponse(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Add("Auth-Status", message)

	if message == "OK" {
		if r.Header.Get("Auth-Method") == "cram-md5" {
			w.Header().Add("Auth-Pass", "plain-text-pass")
		}
	}

	if debug {
		log.Println("Sending response, headers:")
		debugHeaders(w.Header())
	}
}

func getProxyConfig(domain string) (types.ProxyConfig, string) {
	proxyConfig := config.Default
	var domainConfig types.ProxyConfig

	jsonBlob, err := ioutil.ReadFile(filepath.Join(configPath, "conf.d", domain))
	if err != nil {
		return proxyConfig, ""
	}

	err = json.Unmarshal(jsonBlob, &domainConfig)
	if err != nil {
		return proxyConfig, "unable to load proxy config"
	}

	// check if we need to apply a template
	if domainConfig.Template != "" {
		if templateConfig, templateFound := config.Templates[domainConfig.Template]; templateFound == true {
			proxyConfig.Apply(&templateConfig)
		}
	}

	// ...
	proxyConfig.Apply(&domainConfig)

	return proxyConfig, ""
}

func getAuthServerAndPort(w http.ResponseWriter, r *http.Request, domain string) (err string) {
	proxyConfig, cacheFound := proxyConfigCache[domain]

	if cacheFound == false || (cacheFound == true && time.Now().After(proxyConfig.Timeout)) {
		// get proxy config
		proxyConfig, err = getProxyConfig(domain)
		if err != "" {
			return err
		}

		proxyConfigCache[domain] = proxyConfig
		w.Header().Add("X-Cache", "MISS")
	} else {
		w.Header().Add("X-Cache", "HIT")
	}

	// get auth ip and port
	protocol := r.Header.Get("Auth-Protocol")
	ip := proxyConfig.IP(protocol)
	port := proxyConfig.Port(protocol)

	// check if ip and port was found
	if ip == "" || port == 0 {
		return fmt.Sprintf("unable to find proxy server or port for protocol: '%s'", protocol)
	}

	mu.Lock()
	defer mu.Unlock()

	// extend cache timeout
	proxyConfig.Timeout = time.Now().Add(timeout)
	proxyConfigCache[domain] = proxyConfig

	// set auth headers
	w.Header().Add("Auth-Server", ip)
	w.Header().Add("Auth-Port", strconv.Itoa(port))

	// no error occured
	return ""
}

func handleMailProxyAuth(w http.ResponseWriter, r *http.Request) {
	if debug {
		log.Println("Received request, headers:")
		debugHeaders(r.Header)
	}
	if authKey != "" && r.Header.Get(authHeader) != authKey {
		if debug {
			log.Println("Invalid auth key")
		}
		handleResponse(w, r, "invalid auth key, check your configuration")
		return
	}

	user := r.Header.Get("Auth-User")
	if user == "" || r.Header.Get("Auth-Pass") == "" {
		if debug {
			log.Println("Username or password are missing")
		}
		handleResponse(w, r, "username and password are required")
		return
	}

	// validate user as email address
	re := regexp.MustCompile("(.+)@(.+\\..+)")
	if re.Match([]byte(user)) == false {
		if debug {
			log.Println("Invalid email address: " + user)
		}
		handleResponse(w, r, "please use a valid email address")
		return
	}

	// user parts consist of [email, name, domain]
	userParts := re.FindStringSubmatch(user)
	if len(userParts) != 3 {
		if debug {
			log.Println("Invalid email address: " + user)
		}
		handleResponse(w, r, "invalid email address")
		return
	}

	// get domain proxy server and port
	err := getAuthServerAndPort(w, r, userParts[2])
	if err != "" {
		log.Println(err)
		handleResponse(w, r, err)
		return
	}

	// ...
	handleResponse(w, r, "OK")
}

func main() {
	// cleanup expired cache entries
	go func() {
		for {
			for domain, proxyConfig := range proxyConfigCache {
				if time.Now().After(proxyConfig.Timeout) {
					delete(proxyConfigCache, domain)
				}
			}

			time.Sleep(cleanup)
		}
	}()

	// handle mail proxy auth
	http.HandleFunc("/", handleMailProxyAuth)

	// start (keep things running)
	log.Println("Starting server, listening on " + listen)
	log.Println(http.ListenAndServe(listen, nil))
}
