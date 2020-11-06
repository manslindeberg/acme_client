package main

import (
	"crypto/ecdsa"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func requestOrder(orderUrl string, ordr interface{}, client *http.Client, header *hdrKid, key *ecdsa.PrivateKey, postAsGet bool) (*ord, string, string, error) {

	resp, body, err := postHTTP(orderUrl, ordr, client, header, key, postAsGet)

	if err != nil {
		log.WithError(err).Error("Failed to request Order")
	}

	nonce := resp.Header.Get("Replay-Nonce")
	location := resp.Header.Get("Location")

	var ordResp ord
	err = json.Unmarshal(body, &ordResp)

	if err != nil {
		log.WithError(err).Error("Failed to Unmarshal Order Response")
	}
	return &ordResp, nonce, location, err
}
