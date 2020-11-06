package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

func postHTTP(url string, body interface{}, client *http.Client, header interface{}, key *ecdsa.PrivateKey, postAsGet bool) (*http.Response, []byte, error) {

	// encodes and signes jws payload and
	jwsBody := getJWS(key, &body, &header, postAsGet)
	jsonJwsBody, _ := json.Marshal(jwsBody)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonJwsBody))
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := client.Do(req)

	if err != nil {
		log.WithError(err).Error("Post Fail")
	}

	defer resp.Body.Close()
	respBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(respBody))
	return resp, respBody, err
}

func getInitialTLSClient(caCert string) *http.Client {

	/*// reads .pem certificates and generates RSA key-pair
	clientCertPem, err := tls.LoadX509KeyPair(clientCa, clientKey)
	if err != nil {
		log.Fatal(err)
	}

	caCertPem, err := ioutil.ReadFile(caCert)
	if err != nil {
		log.Fatal(err)
	}

	// create new set of certificate and adds caCert to the set
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPem)

	// adds caCert to trusted root certificates and loads the
	// clients key-pair to tls configuration
	configTls := &tls.Config{
		Certificates: []tls.Certificate{clientCertPem},
		RootCAs:      certPool,
	}

	// apply tls config to Transport
	configTls.BuildNameToCertificate()
	configTransport := &http.Transport{TLSClientConfig: configTls}

	return &http.Client{Transport: configTransport}*/
	cert, _ := ioutil.ReadFile(caCert)
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cert)

	config := &tls.Config{RootCAs: certPool}
	config.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: config}
	return &http.Client{Transport: transport}

}
