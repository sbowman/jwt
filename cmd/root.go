package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sbowman/jwt/handler"
	"github.com/sbowman/jwt/tokens"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "server",
	Short: "A basic JWT client/server example",
	Run: func(cmd *cobra.Command, args []string) {
		// Cache the server signing keys in memory
		loadKeys()

		// Setup an HTTP server
		listen := viper.GetString("http.listen")
		fmt.Printf("Listening for incoming HTTP connections on %s\n", listen)

		router := handler.Routes()

		if err := http.ListenAndServe(listen, router); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start server: %s\n", err)
			os.Exit(1)
		}
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().Bool("jwt.relax", false, "skip token expiration (development and testing)")
	RootCmd.PersistentFlags().String("jwt.keys", "./keys", "directory to look for JWT public/private signing keys")
	RootCmd.PersistentFlags().Int("bcrypt.cost", 10, "bcrypt default cost (higher is slower but more secure; max 31)")

	RootCmd.Flags().String("http.listen", ":9800", "listen for HTTP connections on this interface")

	viper.BindPFlag("jwt.relax", RootCmd.PersistentFlags().Lookup("jwt.relax"))
	viper.BindPFlag("jwt.keys", RootCmd.PersistentFlags().Lookup("jwt.keys"))
	viper.BindPFlag("bcrypt.cost", RootCmd.PersistentFlags().Lookup("bcrypt.cost"))

	viper.BindPFlag("http.listen", RootCmd.Flags().Lookup("http.listen"))
}

// Loads and caches available keys for decoding JWT.  The latest key is stored
// separately in tokens.CurrentKey, and will be used to sign any new JSON Web
// Tokens issued by the server.
//
// To expire a key, simply delete it from the "jwt.keys" directory and bounce
// the server.
func loadKeys() {
	directory := viper.GetString("jwt.keys")
	tokens.LoadKeys(directory)

	if len(tokens.Keys) > 0 {
		var keys []string
		for key := range tokens.Keys {
			keys = append(keys, key)
		}

		fmt.Printf("Loaded RSA keys: %s\n", strings.Join(keys, ", "))
	} else {
		fmt.Fprintf(os.Stderr, "No RSA keys loaded!")
		return
	}

	fmt.Printf("Current key ID used for signing JWT: %s\n", tokens.CurrentKey.ID)
}
