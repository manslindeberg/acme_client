package main

import (
	"time"
)

type rev struct {
	Cert string `json:"certificate"`
}

type csr struct {
	Req string `json:"csr"`
}

type nonce struct {
	Nonce string `json:"Replay-Nonce"`
	Cache string `json:"Cache-Control"`
}

type dir struct {
	NewAcc   string  `json:"newAccount"`
	NewNonce string  `json:"newNonce"`
	NewOrd   string  `json:"newOrder"`
	NewAuth  string  `json:"newAuthz"`
	RevCert  string  `json:"revokeCert"`
	Key      string  `json:"keyChanges"`
	Meta     dirMeta `json:"meta"`
}

type dirMeta struct {
	Terms  string `json:"termsOfService"`
	Web    string `json:"website"`
	CaIds  string `json:"caaIdentities"`
	ExtAcc string `json:"externalAccountRequired"`
}

type jws struct {
	Data string `json:"payload"`
	Hdr  string `json:"protected"`
	Sign string `json:"signature"`
}

type hdrJwk struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
	Jwk   jwk    `json:"jwk"`
}

type hdrKid struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
	Kid   string `json:"kid"`
}
type jwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type acc struct {
	Stats string   `json:"status"`
	Cont  []string `json:"contact"`
	Terms bool     `json:"termsOfServiceAgreed"`
	Ords  string   `json:"orders"`
}

type ord struct {
	Stats string   `json:"status"`
	Exp   string   `json:"expires"`
	Ids   []id     `json:"identifiers"`
	Bef   string   `json:"notBefore"`
	After string   `json:"notAfter"`
	Auths []string `json:"authorizations"`
	Fin   string   `json:"finalize"`
	Cert  string   `json:"certificate"`
}

type auth struct {
	ID     id        `json:"identifier"`
	Stats  string    `json:"status"`
	Exp    time.Time `json:"expires"`
	Challs []chall   `json:"challenges"`
	Wc     bool      `json:"wildcard"`
}

type chall struct {
	Type  string `json:"type"`
	Token string `json:"token"`
	URL   string `json:"url"`
	Stats string `json:"status"`
	Valid string `json:"validates"`
	Err   prob   `json:"error"`
}

type id struct {
	Type string `json:"type"`
	Val  string `json:"value"`
}

type prob struct {
	Type    string     `json:"type"`
	Det     string     `json:"detail,omitempty"`
	Stats   int        `json:"status,omitempty"`
	Ins     string     `json:"instance,omitempty"`
	Subprob []subprobs `json:"subproblems,omitempty"`
}

type subprobs struct {
	Type string `json:"type"`
	Det  string `json:"detail"`
	ID   id     `json:"identifier"`
}
