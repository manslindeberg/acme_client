package main

import (
	"log"
	"net/http"
)

func requestNonce(client *http.Client, nonceURL string) string {

	req, err := http.NewRequest("HEAD", nonceURL, nil)

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

	return resp.Header.Get("Replay-Nonce")
}
