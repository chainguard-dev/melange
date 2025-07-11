package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.Info("Starting test application")
	
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Test executed")
		},
	}
	
	if err := cmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}