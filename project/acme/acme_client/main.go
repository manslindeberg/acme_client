package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

const post = false
const postAsGet = true
const challTimeOut = 20

const httpServer = "http://127.0.0.1:5002"
const httpsServer = "http://127.0.0.1:5001"

var opts struct {
	Challenge string   `long:"type" description:"Sets chall type to http-01" required:"true"`
	Directory string   `long:"dir" decription:"URL of the ACME server directory" required:"true"`
	Domain    []string `long:"domain" description:"Domain name of the customer server" required:"true"`
	Revoke    bool     `long:"revoke" description:"Sets the client to immedietly revoke the cert after obtaining it"`
	Record    string   `long:"record" description:"IPv4 address which must be returned for all A and AAAA-recordr queries" required:"true"`
}

func main() {

	_, err := flags.ParseArgs(&opts, os.Args)

	if err != nil {
		log.WithError(err).Error("Failed to parse command line arguments...Exiting")
		os.Exit(0)
	}

	var revoke bool
	var challType string
	var dirURL string
	var domNms []string
	var domains int

	var accn acc
	var accLoc string

	var webHdr hdrJwk
	var authHdr hdrKid

	var ordr ord
	var ids []id
	var ordrLoc string

	var authLocs []string
	var authResps []*auth

	switch opts.Challenge {
	case "http01":
		challType = "http-01"
	case "dns01":
		challType = "dns-01"
	default:
		log.WithError(err).Error("Could not find a valid chall type...Exiting")
		os.Exit(0)
	}

	dirURL = opts.Directory
	domNms = opts.Domain
	domains = len(domNms)
	revoke = opts.Revoke

	log.WithFields(log.Fields{"chall Type": challType,
		"Directory":          dirURL,
		"Domain name":        domNms,
		"Revoke Certificate": revoke,
	}).Info("")

	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)

	client := getInitialTLSClient("pebble.minica.pem")

	dir := requestDir(client, dirURL)

	nonce := requestNonce(client, dir.NewNonce)

	key := genEcdsaKey()

	setJWKHeader(&webHdr, nonce, dir.NewAcc, &key.PublicKey)

	accn.Terms = true

	accResponse, nonce, accLoc, err := requestAccount(dir.NewAcc, &accn, client, &webHdr, key, post)

	if err != nil {
		log.WithError(err).Error("Failed to initialize ordr object...Exiting")
		os.Exit(0)
	} else {
		log.WithField("Status:", accResponse.Stats).Info("New acc")
	}

	setKIDHeader(&authHdr, nonce, dir.NewOrd, accLoc)

	ordr.Ids = ids

	// MULTI IDENTIFIER SUPPORT
	for i := 0; i < domains; i++ {
		var idt id
		idt.Type = "dns"
		idt.Val = domNms[i]
		ordr.Ids = append(ordr.Ids, idt)
	}

	ordrResp, nonce, ordrLoc, err := requestOrder(dir.NewOrd, ordr, client, &authHdr, key, post)

	if err != nil {

	} else {
		log.WithFields(log.Fields{
			"Status:":   ordrResp.Stats,
			"Location:": ordrLoc,
		}).Info("New Order")

	}

	authLocs = ordrResp.Auths

	// Sends a authrization request to auth URL for every domain
	for i := 0; i < len(authLocs); i++ {

		var authResp *auth
		setKIDHeader(&authHdr, nonce, authLocs[i], accLoc)
		authResp, nonce, err = requestAuth(authLocs[i], "", client, &authHdr, key, postAsGet)
		authResps = append(authResps, authResp)
	}

	if err != nil {
		log.Error("Failed to request Authorization URL... Exiting")
		os.Exit(0)
	} else {
		challNbrs := len(authResps[0].Challs)
		challTypes := make([]string, challNbrs)

		for i := 0; i < challNbrs; i++ {
			challTypes[i] = authResps[0].Challs[i].Type
		}

		log.WithFields(log.Fields{
			"challs:": challTypes,
		}).Info("New Authorization")
	}

	webKey := webHdr.Jwk
	var challn chall

	var certKey *rsa.PrivateKey
	for j := 0; j < len(authResps); j++ {
		// finds the correct chall struct and posts chall
		for i := 0; i < len(authResps[j].Challs); i++ {
			if authResps[j].Challs[i].Type == challType {
				challn = authResps[j].Challs[i]
				err = postChallenge(&challn, &webKey, domNms[j], httpServer)

				if err != nil {
					log.Error("Failed to post chall to Web Server... Exiting")
				} else {
					log.WithField("Type:", challType).Info("Posted Challenge")
				}
				continue
			}
		}

		setKIDHeader(&authHdr, nonce, challn.URL, accLoc)
		_, nonce, err = requestChallenge(challn.URL, struct{}{}, client, &authHdr, key, post)

		if err != nil {
			os.Exit(0)
		} else {
			log.WithField("chall Type:", challType).Info("Requested ACME server to validate chall")
		}
		var challResp *chall

		// Waiting for chall to be validated
		start := time.Now()
		attempts := 0

		i := 0
		for i < 1 {
			time.Sleep(3 * time.Second)
			attempts++
			setKIDHeader(&authHdr, nonce, challn.URL, accLoc)
			challResp, nonce, err = requestChallenge(challn.URL, "", client, &authHdr, key, postAsGet)

			if err != nil {
				os.Exit(0)
			} else {
				switch challResp.Stats {
				case "valid":
					log.WithField("chall Type:", challType).Info("ACME server chall VALID")
					i = 1
				case "invalid":
					log.WithField("chall Type:", challType).Error("ACME server chall INVALID")
					os.Exit(0)
				case "pending":

					t := time.Now()
					seconds := int64(t.Sub(start) / time.Second)
					if seconds > challTimeOut {
						log.Error("ACME server chall TIMEOUT")
						os.Exit(0)
					}

					log.WithFields(log.Fields{
						"chall Type:": challType,
						"Attempt:":    attempts,
					}).Warn("ACME server chall PENDING")
				}
				continue
			}
		}

		// Waiting for Authorization to be validated
		i = 0
		start = time.Now()
		attempts = 0

		for i < 1 {
			time.Sleep(3 * time.Second)
			attempts++

			var authResp *auth
			setKIDHeader(&authHdr, nonce, authLocs[j], accLoc)
			authResp, nonce, err = requestAuth(authLocs[j], "", client, &authHdr, key, postAsGet)

			if err != nil {
				os.Exit(0)
			} else {
				switch authResp.Stats {
				case "valid":
					log.Info("ACME server Authorization VALID")
					i = 1

				case "invalid":
					log.Error("ACME server Authorization INVALID... Exiting")
					os.Exit(0)
				case "pending":

					t := time.Now()
					seconds := int64(t.Sub(start) / time.Second)
					if seconds > challTimeOut {
						log.Error("ACME server Authorization TIMEOUT... Exiting")
						os.Exit(0)
					}

					log.WithFields(log.Fields{
						"chall Type:": challType,
						"Attempt:":    attempts,
					}).Warn("ACME server Authorization PENDING")
				}
			}
		}
	}
	// Both AUTHORIZATIONS COMPLETED ->  Waiting for Order to be ready
	i := 0
	start := time.Now()
	attempts := 0

	for i < 1 {
		time.Sleep(3 * time.Second)
		attempts++

		setKIDHeader(&authHdr, nonce, ordrLoc, accLoc)
		ordrResp, nonce, ordrLoc, err = requestOrder(ordrLoc, "", client, &authHdr, key, postAsGet)

		if err != nil {
			os.Exit(0)
		} else {
			switch ordrResp.Stats {
			case "ready":
				log.Info("ACME server Order  VALID")
				i = 1

			case "invalid":
				log.Error("ACME server Order  INVALID... Exiting")
				os.Exit(0)
			case "pending":

				t := time.Now()
				secs := int64(t.Sub(start) / time.Second)
				if secs > challTimeOut {
					log.Error("ACME server Order  TIMEOUT... Exiting")
					os.Exit(0)
				}

				log.WithFields(log.Fields{
					"chall Type:": challType,
					"Attempt:":    attempts,
				}).Warn("ACME server Authorization PENDING")
			}
		}
	}

	// Send CSR to finalize URL in ordr to retreive Certificate URL
	finURL := ordrResp.Fin

	var req string
	req, certKey, err = genCertRequest(domNms[0], domNms)

	var certReq csr
	certReq.Req = req

	setKIDHeader(&authHdr, nonce, finURL, accLoc)
	ordrResp, nonce, ordrLoc, err = requestCert(finURL, certReq, client, &authHdr, key, post)

	// Waiting for Order to complete
	i = 0
	start = time.Now()
	attempts = 0

	for i < 1 {
		time.Sleep(3 * time.Second)

		setKIDHeader(&authHdr, nonce, ordrLoc, accLoc)
		ordrResp, nonce, ordrLoc, err = requestOrder(ordrLoc, "", client, &authHdr, key, postAsGet)
		if err != nil {
			os.Exit(0)
		} else {
			switch ordrResp.Stats {
			case "valid":
				log.Info("ACME server Order  VALID")
				i = 1

			case "invalid":
				log.Error("ACME server Order  INVALID... Exiting")
				os.Exit(0)
			case "ready":

				t := time.Now()
				seconds := int64(t.Sub(start) / time.Second)
				if seconds > challTimeOut {
					log.Error("ACME server Order  TIMEOUT... Exiting")
					os.Exit(0)
				}

				log.WithFields(log.Fields{
					"chall Type:": challType,
					"Attempt:":    attempts,
				}).Warn("ACME server ordr PENDING")
			}
		}
	}

	certLocation := ordrResp.Cert
	setKIDHeader(&authHdr, nonce, certLocation, accLoc)
	cert, nonce, err := fetchCert(certLocation, client, &authHdr, key)

	// Revokes certificate if parsed at cmd line input
	if revoke {
		var rev rev
		block, _ := pem.Decode([]byte(cert))
		certDer := block.Bytes
		rev.Cert = base64.RawURLEncoding.EncodeToString(certDer)

		setKIDHeader(&authHdr, nonce, dir.RevCert, accLoc)
		err = revokeCert(dir.RevCert, client, &authHdr, key, &rev)

		if err != nil {
			log.WithError(err).Error("Failed to revoke cert... Exiting")
			os.Exit(0)
		} else {
			log.Info("Certificate Revoked Successfull")

		}
	}

	err = uploadCert(cert, certKey, "")
	log.WithField("Location", "main").Info("Certificate Uploaded")
}
