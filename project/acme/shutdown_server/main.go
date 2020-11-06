package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

// www.mynewmegaawesomeacmewebsite.com
func main() {

	log.WithField("Port", 5003).Info("Sucessfully Initialized Shutdown Server")
	http.HandleFunc("/", defaultHandler)
	http.ListenAndServe(":5003", nil)
}

func defaultHandler(resp http.ResponseWriter, req *http.Request) {

	fmt.Fprint(resp, "Thank you for visiting my new mega awesome acme website ❤️i")
	os.Exit(0)
}
