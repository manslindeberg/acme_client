package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// Sends a HTTP directory URL request to ACME server
func requestDir(client *http.Client, dirURL string) *dir {

	req, err := http.NewRequest("GET", dirURL, nil)
	req.Header.Add("User-Agent", "application/json")
	req.Header.Add("Accept-Language", "en-US")

	resp, err := client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	if err != nil {
		log.Fatal(err)
	}

	var dirc dir
	json.NewDecoder(resp.Body).Decode(&dirc)
	return &dirc
}
