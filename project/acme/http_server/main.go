package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

var challengePosted bool
var keyAuthorization string

// www.mynewmegaawesomeacmewebsite.com
func main() {
	challengePosted = false

	fmt.Println("Starting HTTP Challenge Server")

	http.HandleFunc("/", defaultHandler)
	http.HandleFunc("/.well-known/acme-challenge/", challengeHandler)
	http.ListenAndServe(":5002", nil)
}

func defaultHandler(resp http.ResponseWriter, req *http.Request) {

	fmt.Fprint(resp, "Thank you for visiting my new mega awesome acme website")
}

func challengeHandler(resp http.ResponseWriter, req *http.Request) {

	method := req.Method

	if method == "GET" {
		if challengePosted {
			fmt.Fprint(resp, keyAuthorization)
		} else {
			fmt.Fprint(resp, "Thank you for visiting acme challenge")
		}
	}

	if method == "POST" {

		key, err := ioutil.ReadAll(req.Body)
		keyAuthorization = string(key)
		challengePosted = true
		if err != nil {
			log.WithField("Error", err).Warn("Couldn't parse POST request")
			return
		}
	}
}
