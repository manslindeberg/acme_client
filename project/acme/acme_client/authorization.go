package main

import (
	"crypto/ecdsa"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func requestAuth(authURL string, authz interface{}, client *http.Client, hdr *hdrKid, key *ecdsa.PrivateKey, postAsGet bool) (*auth, string, error) {
	// encodes and signes jws payload and

	resp, body, err := postHTTP(authURL, authz, client, hdr, key, postAsGet)

	if err != nil {
		log.WithError(err).Error("Failed to request Authorization")
	}

	nonce := resp.Header.Get("Replay-Nonce")

	var authResp auth
	err = json.Unmarshal(body, &authResp)

	if err != nil {
		log.WithError(err).Error("Failed to Unmarshal Authorization Response")
	}

	return &authResp, nonce, err
}
