package cmd

import "github.com/spf13/cobra"

// Generate commands
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate required keys, etc.",
}

func init() {
	RootCmd.AddCommand(generateCmd)
}
