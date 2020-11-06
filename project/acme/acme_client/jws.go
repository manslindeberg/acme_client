package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

func encodeData(data interface{}) string {

	// serializes struct to a json-encoded slice
	jsonData, err := json.Marshal(data)

	if err != nil {
		fmt.Printf("Error: %s", err)
	}

	b64Data := base64.RawURLEncoding.EncodeToString(jsonData)
	/*b64Data = strings.Replace(b64Data, "+", "-", -1)
	b64Data = strings.Replace(b64Data, "/", "_", -1)
	b64Data = strings.Replace(b64Data, "=", "", -1)*/

	return b64Data
}

func encodeSign(data []byte) string {
	b64Data := base64.RawURLEncoding.EncodeToString(data)
	/*b64Data = strings.Replace(b64Data, "+", "-", -1)
	b64Data = strings.Replace(b64Data, "/", "_", -1)
	b64Data = strings.Replace(b64Data, "=", "", -1)*/

	return b64Data
}

func setJWK(pubKey *jwk, key *ecdsa.PublicKey) {

	param := key.Curve.Params()
	size := param.BitSize / 8
	if param.BitSize%8 != 0 {
		size++
	}

	// encodes and signes jws payload and
	pubKey.Crv = param.Name
	pubKey.Kty = "EC"
	pubKey.X = base64.RawURLEncoding.EncodeToString(key.X.Bytes())
	pubKey.Y = base64.RawURLEncoding.EncodeToString(key.Y.Bytes())
}

func getJWS(privKey *ecdsa.PrivateKey, data interface{}, hdr interface{}, postAsGet bool) *jws {

	h256 := sha256.New()
	var payLoad string

	if !postAsGet {
		payLoad = encodeData(data)
	}

	// Base64Url Encode
	pHeader := encodeData(hdr)

	//Concatenate
	signInput := []byte(pHeader + "." + payLoad)

	io.WriteString(h256, string(signInput))
	signHash := h256.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, signHash)

	if err != nil {
		fmt.Printf("Error: %s", err)
	}
	sign := append(r.Bytes(), s.Bytes()...)
	encSign := encodeSign(sign)

	jwsBody := jws{
		Data: payLoad,
		Hdr:  pHeader,
		Sign: encSign,
	}

	return &jwsBody
}

func genEcdsaKey() *ecdsa.PrivateKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		fmt.Printf("Error: %s", err)
	}
	return privKey
}

func setJWKHeader(hdr *hdrJwk, nonce, url string, key *ecdsa.PublicKey) {
	hdr.Alg = "ES256"
	hdr.Nonce = nonce
	hdr.URL = url
	var webKey jwk
	setJWK(&webKey, key)
	hdr.Jwk = webKey
}

func setKIDHeader(hdr *hdrKid, nonce, url, kid string) {
	hdr.Alg = "ES256"
	hdr.Nonce = nonce
	hdr.URL = url
	hdr.Kid = kid
}
