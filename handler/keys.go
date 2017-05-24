package handler

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/sbowman/jwt/tokens"
)

// PublicKeys returns a map of key ID to public keys available on this server
// for confirming JWT tokens.
func PublicKeys(out http.ResponseWriter, req *http.Request) {
	keys := make(map[string]string)

	for id, key := range tokens.Keys {
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}

		block := &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pub,
		}
		keys[id] = string(pem.EncodeToMemory(block))
	}

	ok(out, req, keys)
}
