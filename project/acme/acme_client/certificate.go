package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
)

func genCertRequest(dom string, dnss []string) (string, *rsa.PrivateKey, error) {

	certKey, err := rsa.GenerateKey(rand.Reader, 1024)

	if err != nil {
		log.WithError(err).Error("Failed to Generate RSA keys... Exiting")
		os.Exit(0)
	}

	csrTemplate := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: dom},
		DNSNames:           dnss,
	}

	csrRequest, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)

	if err != nil {
		log.WithError(err).Error("Failed to Certificate")
	}

	csrb64 := b64.RawURLEncoding.EncodeToString([]byte(csrRequest))

	return csrb64, certKey, err
}

func requestCert(certURL string, cert interface{}, client *http.Client, hdr *hdrKid, key *ecdsa.PrivateKey, postAsGet bool) (*ord, string, string, error) {

	resp, body, err := postHTTP(certURL, cert, client, hdr, key, postAsGet)

	if err != nil {
		log.WithError(err).Error("Failed to request certificate")
	}

	nonce := resp.Header.Get("Replay-Nonce")
	location := resp.Header.Get("Location")

	var ordResp ord
	err = json.Unmarshal(body, &ordResp)

	if err != nil {
		log.WithError(err).Error("Failed to Unmarshal Certificate Response")
	}

	return &ordResp, nonce, location, err
}

func fetchCert(certURL string, client *http.Client, hdr *hdrKid, key *ecdsa.PrivateKey) ([]byte, string, error) {

	resp, body, err := postHTTP(certURL, "", client, hdr, key, postAsGet)

	nonce := resp.Header.Get("Replay-Nonce")

	if err != nil {
		log.WithError(err).Error("Failed to get certificate")
		return nil, "", err
	}

	return body, nonce, err

}

func revokeCert(revURL string, client *http.Client, hdr *hdrKid, key *ecdsa.PrivateKey, cert *rev) error {

	_, _, err := postHTTP(revURL, cert, client, hdr, key, post)

	return err

}

func uploadCert(cert []byte, privateKey *rsa.PrivateKey, path string) error {

	//certPath, err := filepath.Abs(path + "acme_cert.pem")
	//certPath, err := filepath.Abs(path + "acme_cert.pem")
	err := ioutil.WriteFile("acme_cert.pem", cert, 0644)

	if err != nil {
		log.WithError(err).Error("Failed to upload certificate to https webserver")
	}

	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	//keyPath, err := filepath.Abs(path + "acme_key.pem")
	//	keyPath, err := filepath.Abs(path + "acme_key.pem")
	err = ioutil.WriteFile("acme_key.pem", privatePEM, 0644)

	if err != nil {
		log.WithError(err).Error("Failed to upload RSA key to https webserver...Exiting")
	}

	return err
}
