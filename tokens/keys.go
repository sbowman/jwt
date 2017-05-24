package tokens

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	// Keys maps the key ID (filename) to the matching RSA key used to sign
	// JWT tokens.
	Keys = make(map[string]*rsa.PrivateKey)

	// CurrentKey is the key currently used to sign JWT tokens (latest).
	CurrentKey Key
)

// Key encapsulate information about the JWT token key.
type Key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
}

// LoadKeys loads the RSA private keys for use in signing JWT tokens.
func LoadKeys(directory string) {
	// Clear existing keys
	Keys = make(map[string]*rsa.PrivateKey)

	info, err := os.Stat(directory)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "Keys directory does not exist; have you generated your secure keys?")
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Unable to read keys from %s: %s\n", directory, err)
		os.Exit(1)
	}

	if !info.IsDir() {
		fmt.Fprintln(os.Stderr, "Please supply a valid directory in jwt.keys")
		os.Exit(1)
	}

	filepath.Walk(directory, loadKey)

	// What is the most recent key?
	var current string
	for id := range Keys {
		if current == "" || id > current {
			current = id
		}
	}

	CurrentKey = Key{
		ID:         current,
		PrivateKey: Keys[current],
	}
}

// Load a single key, parse it into an RSA certificate, and cache it.
func loadKey(path string, info os.FileInfo, err error) error {
	if info.IsDir() {
		return err
	}

	if filepath.Ext(path) == ".key" {
		id := filepath.Base(path)
		id = id[:len(id)-4]

		der, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to read key file %s: %s\n", path, err)
			return nil
		}

		cert, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to parse RSA key in %s: %s\n", path, err)
			return nil
		}

		Keys[id] = cert
	}

	return nil
}
