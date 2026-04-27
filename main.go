package main

import (
	"os"

	"github.com/sikalabs/sikalabs-kubernetes-oidc-login/pkg/cmd"
)

func main() {
	if err := cmd.GetCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
