package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"path/filepath"
)

func main() {

	certPath, err := filepath.Abs("../acme_client/acme_cert.pem")
	keyPath, err := filepath.Abs("../acme_client/acme_key.pem")

	if err != nil {
		log.WithError(err).Error("Failed to fetch TLS certificates... Exiting")
		os.Exit(0)
	} else {
		log.WithField("Port", 5001).Info("Sucessfully Initialized HTTPS server")
	}

	http.HandleFunc("/", handler)
	http.ListenAndServeTLS(":5001", certPath, keyPath, nil)
}

func handler(resp http.ResponseWriter, req *http.Request) {

	fmt.Fprint(resp, "This Website uses TLS and got its certificate from Måns Lindebergs ACME client")
}
