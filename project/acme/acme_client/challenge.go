package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"time"
)

// Posts either http-01 or dns-01 challenge
func postChallenge(chall *chall, jwk *jwk, dom, URL string) error {

	var err error
	switch chall.Type {
	case "http-01":
		err = postHTTPChall(chall, jwk, URL)
	case "dns-01":
		err = postDNSChall(chall, jwk, dom)
	}

	return err
}

func requestChallenge(challURL string, challn interface{}, client *http.Client, hdr *hdrKid, key *ecdsa.PrivateKey, postAsGet bool) (*chall, string, error) {

	resp, body, err := postHTTP(challURL, challn, client, hdr, key, postAsGet)

	if err != nil {
		log.WithError(err).Error("Failed to request Challenge")
	}

	nonce := resp.Header.Get("Replay-Nonce")

	var challResp chall
	err = json.Unmarshal(body, &challResp)

	if err != nil {
		log.WithError(err).Error("Failed to unmarshal Challenge reply")
	}
	return &challResp, nonce, err
}

func postHTTPChall(chall *chall, jwk *jwk, serverURL string) error {

	ser, err := json.Marshal(&jwk)

	if err != nil {
		log.WithError(err).Error("Failed to serialize")
	}

	// hash using SHA256
	h256 := sha256.New()
	io.WriteString(h256, string(ser))
	sign := h256.Sum(nil)

	// resulting jwk thumbprint after serializing and hashing
	tPrint := base64.RawURLEncoding.EncodeToString(sign)
	keyAuth := []byte(chall.Token + "." + tPrint)

	tgtURL := serverURL + "/.well-known/acme-challenge/" + chall.Token
	resp, err := http.Post(tgtURL, "text", bytes.NewBuffer(keyAuth))

	if err != nil {
		log.WithError(err).Error("Failed to post Challenge on http server")
	}

	defer resp.Body.Close()

	return err
}

func postDNSChall(challn *chall, jwk *jwk, dom string) error {

	name := "_acme-challenge." + dom + "."

	ser, err := json.Marshal(&jwk)

	if err != nil {
		log.WithError(err).Error("Failed to serialize")
	}

	// hash using SHA256
	h256 := sha256.New()
	io.WriteString(h256, string(ser))
	sign := h256.Sum(nil)

	// resulting jwk thumbprint after serializing and hashing
	tPrint := base64.RawURLEncoding.EncodeToString(sign)
	keyAuth := challn.Token + "." + tPrint

	h256 = sha256.New()
	io.WriteString(h256, string(keyAuth))
	authHash := h256.Sum(nil)

	b64AuthHash := base64.RawURLEncoding.EncodeToString(authHash)
	msg := dns.Msg{}

	msg.SetQuestion(name, dns.TypeTXT)

	client := new(dns.Client)
	_, _, _ = client.Exchange(&msg, "127.0.0.1:10053")

	time.Sleep(1)
	msgTwo := new(dns.Msg)
	msgTwo.SetQuestion(dns.Fqdn(b64AuthHash), dns.TypeTXT)

	_, _, _ = client.Exchange(msgTwo, "127.0.0.1:10053")

	return err
}
