package cmd

import (
	"github.com/sikalabs/sikalabs-kubernetes-oidc-login/pkg/login"
	"github.com/spf13/cobra"
)

var FlagIssuer string
var FlagClientID string
var FlagClientSecret string

func GetCmd() *cobra.Command {
	var Cmd = &cobra.Command{
		Use:   "sikalabs-kubernetes-oidc-login",
		Short: "Perform OIDC login and output Kubernetes ExecCredential for kubectl",
		Args:  cobra.NoArgs,
		Run: func(c *cobra.Command, args []string) {
			login.Login(FlagIssuer, FlagClientID, FlagClientSecret)
		},
	}
	Cmd.Flags().StringVar(&FlagIssuer, "oidc-issuer-url", "", "OIDC Issuer URL")
	Cmd.MarkFlagRequired("oidc-issuer-url")
	Cmd.Flags().StringVar(&FlagClientID, "oidc-client-id", "", "OIDC Client ID")
	Cmd.MarkFlagRequired("oidc-client-id")
	Cmd.Flags().StringVar(&FlagClientSecret, "oidc-client-secret", "", "OIDC Client Secret")
	return Cmd
}
