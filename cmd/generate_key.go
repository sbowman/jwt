package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	uuid "github.com/satori/go.uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Generate new public/private key pair for signing tokens.
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Generate and save the public/private key pair for server-signing JWT tokens",

	Run: func(cmd *cobra.Command, args []string) {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to generate RSA keys: %s\n", err)
			os.Exit(1)
		}

		directory := viper.GetString("jwt.keys")

		if err = os.MkdirAll(directory, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to create directory %s: %s\n", directory, err)
			os.Exit(1)
		}

		// We need these to be ordered...
		id := uuid.NewV1().String()

		der := x509.MarshalPKCS1PrivateKey(pk)
		file := filepath.Join(directory, id+".key")
		if err = ioutil.WriteFile(file, der, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to save key to %s: %s\n", file, err)
			os.Exit(1)
		}

		fmt.Printf("Key written to %s\n", file)
	},
}

func init() {
	generateCmd.AddCommand(keyCmd)
}
