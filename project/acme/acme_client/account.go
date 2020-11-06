package main

import (
	"crypto/ecdsa"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func requestAccount(accURL string, account interface{}, client *http.Client, hdr *hdrJwk, key *ecdsa.PrivateKey, postAsGet bool) (*acc, string, string, error) {

	// filling in account resource data
	resp, body, err := postHTTP(accURL, account, client, hdr, key, postAsGet)

	if err != nil {
		log.WithError(err).Error("Failed to request Account")
	}

	var accResp acc
	err = json.Unmarshal(body, &accResp)

	if err != nil {
		log.WithError(err).Error("Failed to Unmarshal Account Response")
	}

	nonce := resp.Header.Get("Replay-Nonce")
	location := resp.Header.Get("Location")

	return &accResp, nonce, location, err
}
